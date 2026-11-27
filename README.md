# raksa-siem

[![CI](https://github.com/luminariadev/raksa-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-siem/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-siem/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-siem/actions/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/luminariadev/raksa-siem)](https://github.com/luminariadev/raksa-siem/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/)
[![Python SDK 3.11+](https://img.shields.io/badge/python%20sdk-3.11%2B-3776ab.svg)](sdk/python/README.md)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-4c1.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![MCP](https://img.shields.io/badge/MCP-10%20tools-6f42c1.svg)](#mcp-server-integration-raksa-siem-mcp)

Layer 6 (`observability-siem`) of the **Raksa Security Suite**: a fast, clusterless, single-binary security log normalizer, cross-layer correlator, native Sigma YAML engine, continuous tailer, authenticated HTTP/Syslog collector, MCP server, and zero-dependency Python SDK.

`raksa-siem` correlates telemetry from upstream Raksa layers (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`) alongside enterprise host, cloud, container, IDS, and web logs into Raksa Finding Schema v1 incidents, chronological timelines, SARIF 2.1.0 reports, Prometheus metrics, and deduplicated alert routes.

## Highlights (`v0.2.0`)

- **13 Input Formats + Auto-Detection + Bounded `.gz`**: `raksa` (Layer 1-5 Finding JSON reports), `raksa-ndjson`, `auth`, `syslog`, `nginx`, `jsonl`, `cef`, `auditd`, `cloudtrail`, `k8s-audit`, `suricata`, `win-evtx`, and `leef`, with transparent `64 MiB`-capped gzip ingestion.
- **23 Built-In Rules (`SIEM-001`..`502`)**: Covers brute-force bursts, password spraying, compromise-after-failures, multi-IP logins, privilege changes, 4xx/5xx web probes, cross-layer IP/host correlation (`SIEM-201`..`205`), multi-step EQL-style sequences (`SIEM-206`), alert storms, log tampering, native Sigma YAML detections (`SIEM-403`), policy watchlists (`SIEM-501`), and STIX 2.1/CIDR feeds (`SIEM-502`).
- **Native Pure-Go Sigma YAML Engine (`verify-sigma`)**: Compiles multi-document Sigma YAML (`wildcards`, `contains`, `startswith`, `endswith`, `re`, `cidr`, `base64`, `all`, `cased`, recursive `and`/`or`/`not`/`1 of`/`all of`, `timeframe`, and `count() by` aggregations) at `675.6 ns/op` with zero external rule-engine dependencies.
- **STIX 2.1 / CIDR Threat Intel & Asset Criticality**: Ingests STIX 2.1 bundles, CSVs, and CIDR blocklists while automatically escalating finding severity on `tier1` critical assets.
- **Fail-Closed Policy & Baselines**: Waivers require both a non-empty `reason` and non-expired `expires_on`; webhook/Slack/Discord sinks require `https://` (or `localhost` / `127.0.0.1`); deterministic SHA-256 baseline gating integrates cleanly in CI.
- **Continuous Tailer, Syslog UDP/TCP & Authenticated HTTP API**: `watch` handles partial lines, truncation/rotation, `--siem-out`, and `/metrics`; `serve` runs HTTP ingest/query endpoints (`X-API-Key` / Bearer, NDJSON store) alongside bounded `--syslog-udp` and `--syslog-tcp` RFC 3164/5424 listeners.
- **Minimal Dependency Footprint**: Go binary imports only `gopkg.in/yaml.v3 v3.0.1`; Python SDK (`raksa-siem-sdk v0.2.0`) uses 100% Python stdlib (`dependencies = []`).

## Quick Start

### Build & Verify Locally

```bash
git clone https://github.com/luminariadev/raksa-siem.git
cd raksa-siem
go build -ldflags="-s -w" -o raksa-siem ./cmd/raksa-siem
```

Run clean, multi-layer, and enterprise Sigma/sequence fixtures:

```bash
# Clean baseline telemetry -> exit 0, Posture 100/100 (A+)
./raksa-siem analyze testdata/clean --fail-on high --output table

# Multi-layer attack chain (auth + nginx + netguard + pipeguard + iocscan) -> exit 1
./raksa-siem analyze testdata/attack_chain --fail-on high --output sarif > siem.sarif

# Enterprise pipeline (auditd + CloudTrail + K8s Audit + Suricata + WinEVTX + LEEF + Sigma + Sequence + STIX/CIDR + tier1 assets)
./raksa-siem analyze testdata/enterprise --policy testdata/enterprise/enterprise_policy.yml --fail-on high --output json

# Validate Detection-as-Code YAML policy, Sigma rules, and simulate alert delivery
./raksa-siem verify-rules examples/raksa-siem.yml examples/sequence-policy.yml
./raksa-siem verify-sigma testdata/enterprise/sigma_rules
./raksa-siem test-alert --policy examples/raksa-siem.yml --dry-run

# Start HTTP ingest + Syslog UDP/TCP collector
./raksa-siem serve --addr 127.0.0.1:8484 --syslog-udp 127.0.0.1:5514 --syslog-tcp 127.0.0.1:5515 --policy examples/sequence-policy.yml
```

## CLI Subcommands (11)

| Subcommand | Purpose |
| :--- | :--- |
| `analyze` | Normalize logs/reports (13 formats + `.gz`), run 23 rules + Sigma/sequence/TI/assets, exit `0`/`1`/`2`. |
| `correlate` | Correlate upstream Layer 1-5 Raksa JSON/NDJSON reports across IP and host boundaries. |
| `normalize` | Convert raw multi-format telemetry into canonical `schema.Event` JSON or `--ndjson`. |
| `watch` | Tail log files/directories continuously with rotation recovery, `--siem-out`, and `/metrics`. |
| `serve` | Run authenticated HTTP SIEM ingest/query API and optional `--syslog-udp` / `--syslog-tcp` listeners. |
| `verify-rules` | Fail-closed YAML/JSON policy, sequence rule, custom regex, waiver, and sink URL validation. |
| `verify-sigma` | Compile and fail-closed validate native Sigma YAML rule files or directories. |
| `test-alert` | Dispatch a synthetic alert (`--dry-run` by default) to test configured sinks and HMAC signing. |
| `rules` | List built-in `SIEM-001`..`502` rules (`--module` and `--output table|json`). |
| `mcp` | Launch the 10-tool stdio JSON-RPC 2.0 MCP server. |
| `version` | Print binary version, Raksa Schema version (`1.0`), and layer (`siem`). |

Overlay flags `--sigma`, `--threat-intel`, and `--assets` (comma-separated) can be supplied to `analyze`, `correlate`, `watch`, and `serve`.

## Exit Codes

- `0`: Completed with no remaining findings meeting `--fail-on` (default `high`).
- `1`: One or more correlated incidents met or exceeded `--fail-on`.
- `2`: Invalid usage, fail-closed policy/Sigma validation error, or runtime failure.

## Python SDK (`raksa-siem-sdk v0.2.0`)

```bash
pip install ./sdk/python
```

```python
from raksa_siem_sdk import AssetCatalog, AssetEntry, Correlator, SiemClient, ThreatFeed, normalize_file

feed = ThreatFeed()
feed.load_file("examples/stix-feed.json")
assets = AssetCatalog([AssetEntry(host="prod-db-01", tier="tier1", owner="secops")])

events = normalize_file("testdata/enterprise/auditd.log")
findings, timeline = Correlator(threat_feed=feed, asset_catalog=assets).analyze_batch(events)

# Optional HTTP client against `raksa-siem serve`
client = SiemClient("http://127.0.0.1:8484", api_key="your-session-key")
resp = client.ingest(events)
```

See [Python SDK Guide](sdk/python/README.md) for details.

## Benchmarks & Footprint (`v0.2.0`, Windows amd64)

| Metric | Measured Result |
| :--- | :--- |
| Static Go Binary (`-ldflags="-s -w"`) | `8,095,232` bytes (`7.72 MiB`), `1` external module (`gopkg.in/yaml.v3 v3.0.1`) |
| `BenchmarkNormalizeMixed-12` (1,000 events) | `11.07 ms` (`11,071,476 ns/op`, `3,553,074 B/op`, `33,053 allocs/op`) |
| `BenchmarkCorrelateEvents-12` (1,000 events) | `0.49 ms` (`494,785 ns/op`, `1,538,341 B/op`, `56 allocs/op`) |
| `BenchmarkSigmaEval-12` | `675.6 ns/op` (`120 B/op`, `5 allocs/op`) |
| MCP stdio 51-frame burst (`initialize` + 50 calls) | `20.41 ms` total (`0.408 ms/call`) |
| Python SDK `v0.2.0` (`1,000` nginx normalize + correlate) | `22.37 ms` (`0` external deps) |
| Python SDK Wheel (`raksa_siem_sdk-0.2.0-py3-none-any.whl`) | `17,705` bytes |

## MCP Server Integration (`raksa-siem mcp`)

Launch `raksa-siem mcp` over stdio (JSON-RPC 2.0, `2 MiB` bounded line frames) to expose `10` tools to AI coding and security triage agents:

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

## Scope & Boundaries

`raksa-siem` is designed as a lightweight, zero-cluster correlation engine, offline DFIR hunter, CI/CD security gate, and single-binary collector:

- Incident and event persistence in `v0.2.0` uses bounded in-memory sliding windows paired with append-only NDJSON files rather than a clustered external search database.
- Sigma compilation runs natively in pure Go without Python `pysigma` or external transducers, focusing on process creation, cloud audit, Kubernetes, auth, web, DNS/Suricata, and CIDR/regex/base64/count aggregations over normalized fields.
- Offline telemetry ingestion parses Linux auditd, CloudTrail, Kubernetes Audit JSON, Suricata EVE, Windows Event JSON (`win-evtx`), LEEF, CEF, syslog, auth, nginx, JSONL, and upstream Raksa reports without kernel drivers or raw binary Windows `.evtx` memory-mapping libraries.

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
