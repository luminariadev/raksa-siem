"""Tests for zero-dependency Python raksa-siem-sdk."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from raksa_siem_sdk import (
    Correlator,
    SiemClient,
    SiemClientError,
    compute_posture,
    detect_format,
    normalize_line,
    normalize_lines,
    validate_endpoint_url,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_normalizer_all_seven_formats_and_correlator() -> None:
    samples = [
        'Nov 27 10:00:01 app-01 sshd[10]: Failed password for admin from 198.51.100.66 port 5000 ssh2',
        '198.51.100.66 - - [27/Nov/2026:10:00:10 +0000] "GET /.env HTTP/1.1" 404 123 "-" "probe/1.0"',
        'Nov 27 10:00:15 app-01 kernel: [12.3] audit event observed',
        '{"timestamp":"2026-11-27T10:00:20Z","layer":"telemetry","severity":"medium","host":"app-01","message":"timeout"}',
        'CEF:0|Vendor|Guard|1.0|NET-9|Blocked scan|8|src=198.51.100.66 dhost=app-01',
        '{"tool":"raksa-iocscan","layer":"ioc-defense","findings":[{"id":"i1","rule_id":"IOC-001","severity":"critical","description":"ioc hit","evidence":{"host":"app-01","src_ip":"198.51.100.66"}}]}',
    ]
    detected = [detect_format(s) for s in samples]
    assert detected == ["auth", "nginx", "syslog", "jsonl", "cef", "raksa"]

    events = normalize_lines(
        [
            'Nov 27 10:00:01 app-01 sshd[10]: Failed password for admin from 198.51.100.66 port 5001 ssh2',
            'Nov 27 10:00:02 app-01 sshd[11]: Failed password for root from 198.51.100.66 port 5002 ssh2',
            'Nov 27 10:00:03 app-01 sshd[12]: Failed password for ops from 198.51.100.66 port 5003 ssh2',
            'Nov 27 10:00:04 app-01 sshd[13]: Failed password for deploy from 198.51.100.66 port 5004 ssh2',
            'Nov 27 10:00:05 app-01 sshd[14]: Failed password for dev from 198.51.100.66 port 5005 ssh2',
            'Nov 27 10:00:08 app-01 sshd[15]: Accepted password for ops from 198.51.100.66 port 5006 ssh2',
            '{"tool":"raksa-iocscan","layer":"ioc-defense","findings":[{"id":"i1","rule_id":"IOC-001","severity":"critical","description":"ioc","timestamp":"2026-11-27T10:00:30Z","evidence":{"host":"app-01","src_ip":"198.51.100.66"}}]}',
        ],
        default_year=2026,
    )
    corr = Correlator(watched_ips=["198.51.100.66"])
    findings, tl = corr.analyze_batch(events)
    rule_ids = {f.rule_id for f in findings}
    assert {"SIEM-001", "SIEM-002", "SIEM-201", "SIEM-205", "SIEM-501"}.issubset(rule_ids)
    assert tl.total_events == len(events)
    assert compute_posture([]).score == 100
    assert compute_posture(findings).score < 100


def test_client_url_guard_rejects_remote_plaintext_http() -> None:
    assert validate_endpoint_url("https://siem.example.invalid:8484/") == "https://siem.example.invalid:8484"
    assert validate_endpoint_url("http://127.0.0.1:8484") == "http://127.0.0.1:8484"
    with pytest.raises(SiemClientError):
        SiemClient("http://remote-siem.example.invalid:8484")


def test_client_live_go_serve_roundtrip(tmp_path: Path) -> None:
    bin_path = tmp_path / ("raksa-siem.exe" if os.name == "nt" else "raksa-siem")
    subprocess.run(
        ["go", "build", "-o", str(bin_path), "./cmd/raksa-siem"],
        cwd=REPO_ROOT,
        check=True,
    )

    port = _free_port()
    addr = f"127.0.0.1:{port}"
    env = os.environ.copy()
    env["SDK_TEST_API_KEY"] = "sdk-local-test-val"

    proc = subprocess.Popen(
        [str(bin_path), "serve", "--addr", addr, "--api-key-env", "SDK_TEST_API_KEY", "--dry-run"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        client = SiemClient(f"http://{addr}", api_key="sdk-local-test-val", timeout=5.0)
        deadline = time.monotonic() + 8.0
        while True:
            try:
                hz = client.healthz()
                if hz.get("status") == "ok":
                    break
            except SiemClientError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)

        unauth_client = SiemClient(f"http://{addr}")
        with pytest.raises(SiemClientError, match="401"):
            unauth_client.posture()

        lines = [
            "Nov 27 10:00:01 edge-01 sshd[1]: Failed password for root from 203.0.113.55 port 4001 ssh2",
            "Nov 27 10:00:02 edge-01 sshd[2]: Failed password for root from 203.0.113.55 port 4002 ssh2",
            "Nov 27 10:00:03 edge-01 sshd[3]: Failed password for root from 203.0.113.55 port 4003 ssh2",
            "Nov 27 10:00:04 edge-01 sshd[4]: Failed password for root from 203.0.113.55 port 4004 ssh2",
            "Nov 27 10:00:05 edge-01 sshd[5]: Failed password for root from 203.0.113.55 port 4005 ssh2",
        ]
        res = client.ingest(lines, fmt="auth")
        assert res["ingested"] == 5
        assert res["emitted"] >= 1
        assert any(f["rule_id"] == "SIEM-001" for f in res["findings"])

        inc = client.incidents(rule_id="SIEM-001")
        assert inc["total"] >= 1

        tl = client.timeline(src_ip="203.0.113.55")
        assert tl["total_events"] == 5

        posture = client.posture()
        assert posture["posture"]["score"] < 100

        metrics_txt = client.metrics()
        assert "raksa_siem_incidents_total" in metrics_txt
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
