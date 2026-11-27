# raksa-siem-sdk

Zero-dependency Python 3.11+ SDK (`raksa-siem-sdk v0.2.0`) for **raksa-siem** (Layer 6 of the Raksa Security Suite).

## Features

- **100% Standard Library**: `dependencies = []` in `pyproject.toml`.
- **13-Format + Auto + Gzip Log Normalizer**: `normalize_line`, `normalize_lines`, `normalize_file` (with bounded 64 MiB gzip decompression), `normalize_report`, and `detect_format` covering `raksa`, `raksa-ndjson`, `auth`, `syslog`, `nginx`, `jsonl`, `cef`, `auditd`, `cloudtrail`, `k8s-audit`, `suricata`, `win-evtx`, and `leef`.
- **Stateful Correlator, Sequence Rules, Threat Intel & Asset Criticality**: In-process `Correlator`, `SequenceRule` (`SIEM-206`), `ThreatFeed` (STIX 2.1 + CIDR via stdlib `ipaddress`), `AssetCatalog` tier-1 severity escalation, `build_timeline`, and `compute_posture` (`0-100`, `A+`..`F`).
- **Fail-Closed HTTP Client**: `SiemClient` over stdlib `urllib.request` with `validate_endpoint_url` (requires HTTPS remotely or `localhost` / `127.0.0.1`) and optional `X-API-Key` header support.

## Installation

```bash
pip install ./sdk/python
```

## Quick Example

```python
from raksa_siem_sdk import Correlator, SiemClient, normalize_lines

events = normalize_lines([
    'Nov 27 10:00:01 app-01 sshd[10]: Failed password for admin from 198.51.100.66 port 5001 ssh2',
    '198.51.100.66 - - [27/Nov/2026:10:00:10 +0000] "GET /.env HTTP/1.1" 404 162 "-" "probe"',
])
findings, timeline = Correlator().analyze_batch(events)

# Optional HTTP client against `raksa-siem serve`
client = SiemClient("http://127.0.0.1:8484", api_key="your-session-key")
resp = client.ingest(events)
```
