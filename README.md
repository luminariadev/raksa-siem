# raksa-siem

[![CI](https://github.com/luminariadev/raksa-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-siem/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-siem/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-siem/actions/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/luminariadev/raksa-siem)](https://github.com/luminariadev/raksa-siem/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/)
[![Python SDK 3.11+](https://img.shields.io/badge/python%20sdk-3.11%2B-3776ab.svg)](sdk/python/README.md)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-4c1.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![MCP](https://img.shields.io/badge/MCP-12%20tools-6f42c1.svg)](#mcp-server-integration-raksa-siem-mcp)

Layer 6 (`observability-siem`) of the **Raksa Security Suite**: a fast, clusterless, single-binary security log normalizer, cross-layer correlator, native Sigma YAML engine, tamper-evident hash-chained ledger with case triage, TLS/mTLS & RBAC collector, MCP server, and zero-dependency Python SDK.

`raksa-siem` correlates telemetry from upstream Raksa layers (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`) alongside enterprise host, cloud, container, IDS, and web logs into Raksa Finding Schema v1 incidents, offline HTML attack-graph dashboards, MITRE ATT&CK Navigator layers, Prometheus metrics, and reliable DLQ-backed alert routes.

## Highlights (`v0.3.0`)

- **13 Input Formats + Auto-Detection + Bounded `.gz`**: `raksa` (Layer 1-5 Finding JSON reports), `raksa-ndjson`, `auth`, `syslog`, `nginx`, `jsonl`, `cef`, `auditd`, `cloudtrail`, `k8s-audit`, `suricata`, `win-evtx`, and `leef`, with transparent `64 MiB`-capped gzip ingestion.
- **23 Built-In Rules (`SIEM-001`..`502`) & Native Sigma YAML**: Brute-force bursts, password spraying, compromise-after-failures, multi-IP logins, privilege changes, web probes, cross-layer IP/host correlation (`SIEM-201`..`205`), multi-step EQL-style sequences (`SIEM-206`), alert storms, log tampering, native pure-Go Sigma YAML detections (`SIEM-403` at `694.4 ns/op`), policy watchlists (`SIEM-501`), and STIX 2.1/CIDR feeds (`SIEM-502`) with `tier1` asset severity escalation.
- **Tamper-Evident Hash-Chained Ledger & Case Triage**: Date-segmented `siem-YYYY-MM-DD.ndjson` storage chaining every event, finding, and triage update with `SHA-256(seq|timestamp|kind|prev_hash|<compact_payload>)`, startup `--retention-days` pruning, historical search, case workflow (`open`, `ack`, `resolved`, `false_positive`), and independent Go + Python chain verification.
- **7 Report Formats Including Offline HTML Graph & ATT&CK Navigator**: Export `table`, `json`, `sarif` (2.1.0), `markdown`, `ndjson`, self-contained dark-mode `html` (inline SVG entity attack graph, interactive severity filters, zero external CDN/scripts), and `attack-nav` (MITRE ATT&CK Navigator v4.5 JSON).
- **8 Alert Sinks, Exponential Retry & Dead-Letter Queue (DLQ)**: Dispatches deduplicated alerts to HMAC-SHA256 `webhook`, `slack`, `discord`, `telegram`, `teams`, `pagerduty`, `opsgenie`, and `file` with bounded retry backoff (`max_retries` `0..5`), failed-delivery `dlq_path` recording, and `ReplayDLQ`.
- **TLS 1.2+/mTLS, Scoped RBAC & Hot-Reload Server**: `serve` enforces mutual TLS (`--tls-client-ca`), scoped API keys (`--ingest-key-env`, `--read-key-env`, `--admin-key-env`), atomic policy hot-reload via `SIGHUP` or `POST /api/v1/reload`, bounded `--syslog-udp` / `--syslog-tcp`, and Prometheus `/metrics`.
- **Minimal Dependency Footprint**: Go binary imports only `gopkg.in/yaml.v3 v3.0.1`; Python SDK (`raksa-siem-sdk v0.3.0`) uses 100% Python stdlib (`dependencies = []`).

## Quick Start

### Build & Verify Locally

```bash
git clone https://github.com/luminariadev/raksa-siem.git
cd raksa-siem
go build -ldflags="-s -w" -o raksa-siem ./cmd/raksa-siem
```

Run clean, multi-layer, enterprise, offline HTML, and ledger verification workflows:

```bash
# Clean baseline telemetry -> exit 0, Posture 100/100 (A+)
./raksa-siem analyze testdata/clean --fail-on high --output table

# Multi-layer attack chain -> SARIF 2.1.0, offline HTML graph, or MITRE ATT&CK Navigator v4.5
./raksa-siem analyze testdata/attack_chain --fail-on high --output sarif > siem.sarif
./raksa-siem analyze testdata/attack_chain --output html > attack-graph.html
./raksa-siem analyze testdata/attack_chain --output attack-nav > attck-layer.json

# Enterprise pipeline (auditd + CloudTrail + K8s Audit + Suricata + WinEVTX + LEEF + Sigma + Sequence + STIX/CIDR + tier1 assets)
./raksa-siem analyze testdata/enterprise --policy testdata/enterprise/enterprise_policy.yml --fail-on high --output json

# Validate Detection-as-Code YAML policy, Sigma rules, and simulate alert delivery
./raksa-siem verify-rules examples/raksa-siem.yml examples/sequence-policy.yml
./raksa-siem verify-sigma testdata/enterprise/sigma_rules
./raksa-siem test-alert --policy examples/raksa-siem.yml --dry-run

# Start hardened TLS/mTLS HTTP + RBAC + hash-chained ledger + Syslog collector
./raksa-siem serve \
  --addr 127.0.0.1:8484 \
  --syslog-udp 127.0.0.1:5514 \
  --syslog-tcp 127.0.0.1:5515 \
  --ledger-dir ./siem-ledger \
  --retention-days 30 \
  --policy examples/sequence-policy.yml \
  --ingest-key-env SIEM_INGEST_KEY \
  --read-key-env SIEM_READ_KEY \
  --admin-key-env SIEM_ADMIN_KEY

# Triage an incident case and cryptographically verify ledger integrity
./raksa-siem case --dir ./siem-ledger --action update --finding-id fnd-1 --status ack --assignee soc-lead --note "investigating"
./raksa-siem verify-ledger --dir ./siem-ledger --output table
```

## CLI Subcommands (13)

| Subcommand | Purpose |
| :--- | :--- |
| `analyze` | Normalize logs/reports (13 formats + `.gz`), run 23 rules + Sigma/sequence/TI/assets, output 7 formats, exit `0`/`1`/`2`. |
| `correlate` | Correlate upstream Layer 1-5 Raksa JSON/NDJSON reports across IP and host boundaries. |
| `normalize` | Convert raw multi-format telemetry into canonical `schema.Event` JSON or `--ndjson`. |
| `watch` | Tail log files/directories continuously with rotation recovery, `--siem-out`, and `/metrics`. |
| `serve` | Run HTTP/TLS/mTLS RBAC server (`/api/v1/ingest`, `/search`, `/cases`, `/ledger/verify`, `/reload`), `SIGHUP` reload, and Syslog UDP/TCP. |
| `verify-rules` | Fail-closed YAML/JSON policy, sequence rule, custom regex, waiver, and sink URL validation. |
| `verify-sigma` | Compile and fail-closed validate native Sigma YAML rule files or directories. |
| `verify-ledger` | Cryptographically verify `SHA-256` hash-chain continuity across an audit ledger directory (exit `1` on tamper). |
| `case` | List (`--action list`) or triage (`--action update`) incident cases with assignee and audit notes. |
| `test-alert` | Dispatch a synthetic alert (`--dry-run` by default) to test configured sinks, retries, and HMAC signing. |
| `rules` | List built-in `SIEM-001`..`502` rules (`--module` and `--output table|json`). |
| `mcp` | Launch the 12-tool stdio JSON-RPC 2.0 MCP server. |
| `version` | Print binary version (`0.3.0`), Raksa Schema version (`1.0`), and layer (`siem`). |

Overlay flags `--sigma`, `--threat-intel`, and `--assets` (comma-separated) can be supplied to `analyze`, `correlate`, `watch`, and `serve`.

## Exit Codes

- `0`: Completed cleanly with no remaining findings meeting `--fail-on` (or valid ledger on `verify-ledger`).
- `1`: One or more correlated incidents met or exceeded `--fail-on`, or `verify-ledger` detected chain tampering.
- `2`: Invalid usage, fail-closed policy/Sigma validation error, or runtime/IO failure.

## Python SDK (`raksa-siem-sdk v0.3.0`)

```bash
pip install ./sdk/python
```

```python
from raksa_siem_sdk import (
    AssetCatalog,
    AssetEntry,
    Correlator,
    SiemClient,
    ThreatFeed,
    normalize_file,
    verify_ledger_dir,
)

feed = ThreatFeed()
feed.load_file("examples/stix-feed.json")
assets = AssetCatalog([AssetEntry(host="prod-db-01", tier="tier1", owner="secops")])

events = normalize_file("testdata/enterprise/auditd.log")
findings, timeline = Correlator(threat_feed=feed, asset_catalog=assets).analyze_batch(events)

# Optional mTLS & scoped-RBAC HTTP client against `raksa-siem serve`
client = SiemClient(
    "https://siem.example.invalid:8484",
    api_key="your-scoped-token",
    ca_file="ca.pem",
    cert_file="client.crt",
    key_file="client.key",
)
resp = client.ingest(events)
hits = client.search(kind="finding", severity="high")
rep = client.verify_ledger()

# Independent pure-Python verification of Go's SHA-256 ledger segments
local_check = verify_ledger_dir("./siem-ledger")
assert local_check.valid and local_check.tip_hash == rep["tip_hash"]
```

See [Python SDK Guide](sdk/python/README.md) for details.

## Benchmarks & Footprint (`v0.3.0`, Windows amd64)

| Metric | Measured Result |
| :--- | :--- |
| Static Go Binary (`-ldflags="-s -w"`) | `8,688,640` bytes (`8.29 MiB`), `1` external module (`gopkg.in/yaml.v3 v3.0.1`) |
| `BenchmarkNormalizeMixed-12` (1,000 events) | `11.15 ms` (`11,154,432 ns/op`, `3,548,735 B/op`, `33,052 allocs/op`) |
| `BenchmarkCorrelateEvents-12` (1,000 events) | `0.54 ms` (`535,615 ns/op`, `1,538,338 B/op`, `56 allocs/op`) |
| `BenchmarkSigmaEval-12` | `694.4 ns/op` (`120 B/op`, `5 allocs/op`) |
| `BenchmarkLedgerAppendAndVerify-12` | `0.20 ms` (`203,647 ns/op`, `2,558 B/op`, `24 allocs/op`) |
| MCP stdio 51-frame burst (`initialize` + 50 calls) | `22.44 ms` total (`0.449 ms/call`) |
| Python SDK `v0.3.0` (`1,000` nginx normalize + correlate) | `32.17 ms` (`0` external deps) |
| Python SDK Wheel (`raksa_siem_sdk-0.3.0-py3-none-any.whl`) | `20,312` bytes |

## MCP Server Integration (`raksa-siem mcp`)

Launch `raksa-siem mcp` over stdio (JSON-RPC 2.0, `2 MiB` bounded line frames) to expose `12` tools to AI coding and security triage agents:

- `siem_list_rules`: Catalog all 23 built-in `SIEM-*` rules and MITRE D3FEND mappings.
- `siem_analyze_logs`: Normalize and correlate logs (plain or `.gz`, plus Sigma/intel/assets) into Finding Schema v1 reports.
- `siem_correlate_reports`: Correlate upstream Layer 1-5 Raksa JSON/NDJSON reports across hosts and IPs.
- `siem_normalize_events`: Parse mixed logs into canonical `schema.Event` JSON without triggering correlation.
- `siem_build_timeline`: Generate a chronological incident timeline filtered by `src_ip`, `host`, `user`, or `layer`.
- `siem_verify_rules`: Run fail-closed YAML/JSON policy, sequence rule, custom regex, waiver, and sink URL checks.
- `siem_check_suppression`: Evaluate `(rule_id, group_key)` cooldown suppression windows.
- `siem_query_incidents`: Query retained session incidents or an NDJSON incident store.
- `siem_verify_sigma`: Compile and validate native Sigma YAML rule files or directories.
- `siem_match_threat_intel`: Match normalized telemetry or observables against STIX 2.1, CSV, or CIDR feeds.
- `siem_verify_ledger`: Cryptographically verify SHA-256 hash-chain continuity across an audit ledger directory.
- `siem_triage_case`: Transition case triage status (`open`, `ack`, `resolved`, `false_positive`), assignee, and analyst notes in the ledger.

## Scope & Boundaries

`raksa-siem` is designed as a lightweight, clusterless correlation engine, tamper-evident audit recorder, CI/CD security gate, and single-binary collector:

- Historical storage uses local date-segmented SHA-256 hash-chained NDJSON logs (`siem-YYYY-MM-DD.ndjson`) rather than a distributed multi-node database or cluster consensus store.
- Sigma compilation runs natively in pure Go without Python `pysigma`, targeting normalized security event fields across process, cloud audit, Kubernetes, auth, web, DNS/Suricata, CIDR, regex, base64, and `count() by` aggregations.
- Windows Event Log ingestion parses exported JSON (`win-evtx`) alongside Linux auditd, CloudTrail, Kubernetes Audit, Suricata EVE, LEEF, CEF, syslog, auth, nginx, JSONL, and upstream Raksa reports without kernel drivers.
- Signal-based hot-reload uses `SIGHUP` on Unix-like platforms and `POST /api/v1/reload` cross-platform (including Windows).

## Raksa Security Suite

`raksa-siem` shares **Raksa Finding Schema v1** (`schema_version = "1.0"`) across the modular Raksa ecosystem:

- **Layer 1 (`network-defense`)**: [raksa-netguard](https://github.com/luminariadev/raksa-netguard) (Go) - Exposed port audit and real-time firewall/log anomaly detection.
- **Layer 2 (`host-hardening`)**: [raksa-hostguard](https://github.com/luminariadev/raksa-hostguard) (Rust) - Signed parallel SHA-256 FIM, Linux/SSH/Docker CIS hardening, and MCP server.
- **Layer 3 (`web-defense`)**: [raksa-webshield](https://github.com/luminariadev/raksa-webshield) (TypeScript + Go) - Web & API security auditor, semantic SQLi/XSS WAF sidecar, TypeScript SDK, and MCP server.
- **Layer 4 (`devsecops`)**: [raksa-pipeguard](https://github.com/luminariadev/raksa-pipeguard) (Go) - Secret/diff scanner, CycloneDX & SPDX SBOMs, OSV/KEV/EPSS SCA, container tarball auditor, IaC/CI linters, and MCP server.
- **Layer 5 (`ioc-defense`)**: [raksa-iocscan](https://github.com/luminariadev/raksa-iocscan) (Python) - Zero-dep YARA, FastCDC fuzzy hash, PE Authenticode/Fat Mach-O triage, archive/doc scanner, watch daemon, and MCP server.
- **Layer 6 (`observability-siem`)**: `raksa-siem` (Go + Python) - This repository.

## Documentation & Examples

- [Architecture Overview](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Changelog](CHANGELOG.md)
- [Python SDK Guide](sdk/python/README.md)
- [Example Policy](examples/raksa-siem.yml), [Sigma Rules](examples/sigma-rules.yml), [Sequence Policy](examples/sequence-policy.yml), [STIX Feed](examples/stix-feed.json), & [Assets Catalog](examples/assets.yml)

## License

MIT License. See [LICENSE](LICENSE).
