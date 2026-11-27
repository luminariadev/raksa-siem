# raksa-siem-sdk

Zero-dependency Python 3.11+ SDK (`raksa-siem-sdk v0.3.0`) for **raksa-siem** (Layer 6 of the Raksa Security Suite).

## Features

- **100% Standard Library**: `dependencies = []` in `pyproject.toml`.
- **13-Format + Auto + Gzip Log Normalizer**: `normalize_line`, `normalize_lines`, `normalize_file` (with bounded 64 MiB gzip decompression), `normalize_report`, and `detect_format` covering `raksa`, `raksa-ndjson`, `auth`, `syslog`, `nginx`, `jsonl`, `cef`, `auditd`, `cloudtrail`, `k8s-audit`, `suricata`, `win-evtx`, and `leef`.
- **Stateful Correlator, Sequence Rules, Threat Intel & Asset Criticality**: In-process `Correlator`, `SequenceRule` (`SIEM-206`), `ThreatFeed` (STIX 2.1 + CIDR via stdlib `ipaddress`), `AssetCatalog` tier-1 severity escalation, `build_timeline`, and `compute_posture` (`0-100`, `A+`..`F`).
- **mTLS & Scoped RBAC HTTP Client**: `SiemClient` over stdlib `urllib.request` with `validate_endpoint_url`, TLS 1.2+ and client-certificate mTLS (`ca_file`, `cert_file`, `key_file`), scoped API keys (`ingest` / `read` / `admin`), `ingest`, `incidents`, `timeline`, `posture`, `search`, `cases`, `update_case`, `verify_ledger`, and `reload_policy`.
- **Cross-Language Ledger Verifier**: Pure-Python `verify_ledger_dir` verifying SHA-256 hash chains across Go-written `siem-YYYY-MM-DD.ndjson` segments.

## Installation

```bash
pip install ./sdk/python
```

## Quick Example

```python
from raksa_siem_sdk import Correlator, SiemClient, normalize_lines, verify_ledger_dir

events = normalize_lines([
    'Nov 27 10:00:01 app-01 sshd[10]: Failed password for admin from 198.51.100.66 port 5001 ssh2',
    '198.51.100.66 - - [27/Nov/2026:10:00:10 +0000] "GET /.env HTTP/1.1" 404 162 "-" "probe"',
])
findings, timeline = Correlator().analyze_batch(events)

# Optional HTTP/mTLS client against `raksa-siem serve`
client = SiemClient(
    "https://siem.example.invalid:8484",
    api_key="your-scoped-token",
    ca_file="ca.pem",
    cert_file="client.crt",
    key_file="client.key",
)
resp = client.ingest(events)
search_hits = client.search(kind="finding", severity="high")
ledger_status = client.verify_ledger()

# Offline cross-language ledger verification
local_report = verify_ledger_dir("./ledger")
assert local_report.valid
```
