"""Tests for zero-dependency Python raksa-siem-sdk v0.3.0."""

from __future__ import annotations

import gzip
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from raksa_siem_sdk import (
    AssetCatalog,
    AssetEntry,
    Correlator,
    SDK_VERSION,
    SequenceRule,
    SequenceStep,
    SiemClient,
    SiemClientError,
    ThreatFeed,
    compute_posture,
    detect_format,
    normalize_file,
    normalize_lines,
    validate_endpoint_url,
    verify_ledger_dir,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_normalizer_all_thirteen_formats_and_gzip(tmp_path: Path) -> None:
    samples = [
        'Nov 27 10:00:01 app-01 sshd[10]: Failed password for admin from 198.51.100.66 port 5000 ssh2',
        '198.51.100.66 - - [27/Nov/2026:10:00:10 +0000] "GET /.env HTTP/1.1" 404 123 "-" "probe/1.0"',
        'Nov 27 10:00:15 app-01 kernel: [12.3] audit event observed',
        '{"timestamp":"2026-11-27T10:00:20Z","layer":"telemetry","severity":"medium","host":"app-01","message":"timeout"}',
        'CEF:0|Vendor|Guard|1.0|NET-9|Blocked scan|8|src=198.51.100.66 dhost=app-01',
        '{"tool":"raksa-iocscan","layer":"ioc-defense","findings":[{"id":"i1","rule_id":"IOC-001","severity":"critical","description":"ioc hit","evidence":{"host":"app-01","src_ip":"198.51.100.66"}}]}',
        'type=EXECVE msg=audit(1795773615.100:501): node=prod-core-01 acct="ops" exe="/usr/bin/curl" proctitle="curl_stage_probe" addr=198.51.100.66',
        '{"eventTime":"2026-11-27T10:00:25Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging","sourceIPAddress":"198.51.100.66","userIdentity":{"userName":"ci"}}',
        '{"kind":"Event","verb":"create","requestURI":"/api/v1/namespaces/prod/pods/app/exec","user":{"username":"dev"},"sourceIPs":["198.51.100.66"],"objectRef":{"resource":"pods","subresource":"exec"},"responseStatus":{"code":200}}',
        '{"timestamp":"2026-11-27T10:00:30Z","event_type":"alert","src_ip":"198.51.100.66","dest_ip":"203.0.113.1","dest_port":443,"alert":{"signature_id":1001,"signature":"ET Alert","severity":1}}',
        '{"EventID":4625,"TimeCreated":"2026-11-27T10:00:35Z","Computer":"prod-core-01","TargetUserName":"admin","IpAddress":"198.51.100.66"}',
        'LEEF:2.0|IBM|Firewall|1.0|DENY|^|src=198.51.100.66^devName=fw-01^sev=8^msg=Blocked',
    ]
    detected = [detect_format(s) for s in samples]
    assert detected == [
        "auth", "nginx", "syslog", "jsonl", "cef", "raksa",
        "auditd", "cloudtrail", "k8s-audit", "suricata", "win-evtx", "leef",
    ]

    gz_path = tmp_path / "enterprise.log.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as gz:
        gz.write("\n".join(samples[:6]) + "\n")
    gz_events = normalize_file(gz_path)
    assert len(gz_events) == 6


def test_correlator_sequence_threat_intel_and_asset_escalation() -> None:
    feed = ThreatFeed()
    feed.load_file(REPO_ROOT / "testdata" / "enterprise" / "stix_feed.json")
    feed.load_file(REPO_ROOT / "testdata" / "enterprise" / "cidr_blocklist.txt")
    assert feed.count == 3

    cat = AssetCatalog([AssetEntry(host="prod-core-01", tier="tier1", owner="secops")])
    seq = SequenceRule(
        id="PY-SEQ-1",
        title="WinEVTX auth fail -> Auditd exec -> Suricata alert",
        steps=[
            SequenceStep("auth_fail", {"category": "auth", "outcome": "failure"}),
            SequenceStep("exec", {"source_format": "auditd", "action": "exec"}),
            SequenceStep("suricata", {"source_format": "suricata", "category": "network"}),
        ],
    )

    events = normalize_lines([
        '{"EventID":4625,"TimeCreated":"2026-11-27T10:00:01Z","Computer":"prod-core-01","TargetUserName":"admin","IpAddress":"198.51.100.88"}',
        'type=EXECVE msg=audit(1795773615.100:501): node=prod-core-01 acct="ops" exe="/usr/bin/curl" proctitle="curl_stage_probe" addr=198.51.100.88',
        '{"timestamp":"2026-11-27T10:00:30Z","event_type":"alert","src_ip":"198.51.100.88","dest_ip":"203.0.113.10","dest_port":443,"host":"prod-core-01","alert":{"signature_id":2029002,"signature":"ET Alert","severity":2},"dns":{"rrname":"c2-drop.example.invalid"}}',
    ])

    corr = Correlator(threat_feed=feed, asset_catalog=cat, sequence_rules=[seq])
    findings, tl = corr.analyze_batch(events)
    rule_ids = {f.rule_id for f in findings}
    assert {"SIEM-201", "SIEM-206", "SIEM-502"}.issubset(rule_ids)
    assert tl.total_events == 3
    siem502 = next(f for f in findings if f.rule_id == "SIEM-502")
    assert siem502.evidence.get("asset_tier") == "tier1"
    assert compute_posture([]).score == 100


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


def test_client_tls_fail_closed() -> None:
    assert SDK_VERSION == "0.3.0"
    with pytest.raises(SiemClientError, match="key_file requires cert_file"):
        SiemClient("https://siem.example.invalid:8484", key_file="missing-cert.key")


def test_client_rbac_ledger_cases_reload_and_cross_language_verify(tmp_path: Path) -> None:
    bin_path = tmp_path / ("raksa-siem.exe" if os.name == "nt" else "raksa-siem")
    subprocess.run(
        ["go", "build", "-o", str(bin_path), "./cmd/raksa-siem"],
        cwd=REPO_ROOT,
        check=True,
    )

    policy_file = tmp_path / "policy.yml"
    policy_file.write_text("min_severity: low\nauth_burst_threshold: 3\n", encoding="utf-8")
    ledger_dir = tmp_path / "ledger"

    port = _free_port()
    addr = f"127.0.0.1:{port}"
    env = os.environ.copy()
    env["SDK_INGEST_KEY"] = "py-ingest-key"
    env["SDK_READ_KEY"] = "py-read-key"
    env["SDK_ADMIN_KEY"] = "py-admin-key"

    proc = subprocess.Popen(
        [
            str(bin_path),
            "serve",
            "--addr",
            addr,
            "--policy",
            str(policy_file),
            "--ledger-dir",
            str(ledger_dir),
            "--ingest-key-env",
            "SDK_INGEST_KEY",
            "--read-key-env",
            "SDK_READ_KEY",
            "--admin-key-env",
            "SDK_ADMIN_KEY",
            "--dry-run",
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        ingest_client = SiemClient(f"http://{addr}", api_key="py-ingest-key", timeout=5.0)
        read_client = SiemClient(f"http://{addr}", api_key="py-read-key", timeout=5.0)
        admin_client = SiemClient(f"http://{addr}", api_key="py-admin-key", timeout=5.0)

        deadline = time.monotonic() + 8.0
        while True:
            try:
                if read_client.healthz().get("status") == "ok":
                    break
            except SiemClientError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)

        burst = [
            "Nov 27 12:00:01 edge-02 sshd[101]: Failed password for root from 203.0.113.88 port 5101 ssh2",
            "Nov 27 12:00:02 edge-02 sshd[102]: Failed password for root from 203.0.113.88 port 5102 ssh2",
            "Nov 27 12:00:03 edge-02 sshd[103]: Failed password for root from 203.0.113.88 port 5103 ssh2",
        ]

        # Scoped RBAC enforcement
        with pytest.raises(SiemClientError, match="403"):
            read_client.ingest(burst, fmt="auth")
        with pytest.raises(SiemClientError, match="403"):
            ingest_client.search(kind="event")
        with pytest.raises(SiemClientError, match="403"):
            ingest_client.reload_policy()

        ing = ingest_client.ingest(burst, fmt="auth")
        assert ing["emitted"] >= 1
        finding_id = ing["findings"][0]["id"]

        sr = read_client.search(kind="event", src_ip="203.0.113.88")
        assert sr["total"] == 3

        with pytest.raises(SiemClientError, match="403"):
            read_client.update_case(finding_id, "ack")

        updated = admin_client.update_case(
            finding_id,
            "ack",
            assignee="soc-python",
            author="sdk-test",
            note="acknowledged via python sdk",
        )
        assert updated["status"] == "ack"

        listed = read_client.cases(status="ack")
        assert listed["total"] == 1
        assert listed["cases"][0]["finding_id"] == finding_id

        go_rep = read_client.verify_ledger()
        assert go_rep["valid"] is True

        # Cross-language cryptographic SHA-256 verification
        py_rep = verify_ledger_dir(ledger_dir)
        assert py_rep.valid is True
        assert py_rep.entries_checked == go_rep["entries_checked"]
        assert py_rep.tip_hash == go_rep["tip_hash"]

        # Reload policy via admin endpoint
        policy_file.write_text("min_severity: critical\nauth_burst_threshold: 50\n", encoding="utf-8")
        reloaded = admin_client.reload_policy()
        assert reloaded["reloaded"] is True
        after = ingest_client.ingest(
            ["Nov 27 12:01:01 edge-02 sshd[104]: Failed password for admin from 203.0.113.99 port 5104 ssh2"],
            fmt="auth",
        )
        assert after["emitted"] == 0

        # Mutate 1 byte in Go segment file -> Python verifier detects hash mismatch
        seg_files = sorted(ledger_dir.glob("siem-*.ndjson"))
        assert len(seg_files) >= 1
        raw_seg = seg_files[0].read_text(encoding="utf-8")
        seg_files[0].write_text(
            raw_seg.replace("acknowledged via python sdk", "acknowledged via pythXn sdk", 1),
            encoding="utf-8",
        )
        bad_rep = verify_ledger_dir(ledger_dir)
        assert bad_rep.valid is False
        assert bad_rep.broken_segment == seg_files[0].name
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
