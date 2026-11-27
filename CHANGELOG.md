# Changelog

All notable changes to `raksa-siem` are documented in this file.

## [0.3.0] - 2026-11-27

### Added
- **Segmented Hash-Chained Audit Ledger & Case Triage (`internal/ledger`)**: Date-partitioned `siem-YYYY-MM-DD.ndjson` segments where each entry (`seq`, `timestamp`, `kind`, `prev_hash`, `hash`, `payload`) is chained by `SHA-256(seq|timestamp|kind|prev_hash|<compact_payload>)` from a 64-zero genesis hash, paired with startup retention pruning (`--retention-days`), historical search (`Search`), chain integrity checks (`VerifyDir`), and persistent incident case workflows (`open`, `ack`, `resolved`, `false_positive`, assignee, author, audit notes).
- **Offline HTML Attack-Graph & MITRE ATT&CK Navigator v4.5 Reports (`internal/report`)**: Added `--output html` (self-contained dark-mode HTML5 dashboard with inline SVG entity graph, severity filters, zero external assets, and XSS-safe templating) and `--output attack-nav` (MITRE ATT&CK Navigator v4.5 JSON heatmap export), bringing supported output formats to 7.
- **Reliable Alert Routing, DLQ & Enterprise Sinks (`internal/policy`, `internal/router`)**: Added bounded exponential retry backoff on network/429/5xx failures (`max_retries` default `3`, clamped `0..5`), NDJSON dead-letter queue persistence (`dlq_path`), `ReplayDLQ`, and native `teams`, `pagerduty`, and `opsgenie` webhook sinks (8 total sink types alongside HMAC `webhook`, `slack`, `discord`, `telegram`, and `file`).
- **TLS 1.2+/mTLS, Scoped RBAC & Hot-Reload Server (`internal/server`)**: Added `--tls-cert`, `--tls-key`, and `--tls-client-ca` mutual TLS enforcement (`tls.RequireAndVerifyClientCert`), scoped constant-time API tokens (`--ingest-key-env`, `--read-key-env`, `--admin-key-env` with bounded 401/403 request body draining), `SIGHUP` + `POST /api/v1/reload` atomic policy reload, `/api/v1/search`, `/api/v1/cases`, `/api/v1/ledger/verify`, and Prometheus ledger/case gauges.
- **13-Subcommand CLI & 12-Tool MCP Server (`cmd/raksa-siem`, `internal/mcp`)**: Added CLI subcommands `verify-ledger` and `case` plus MCP tools `siem_verify_ledger` and `siem_triage_case`.
- **Python SDK v0.3.0 (`raksa-siem-sdk`)**: Added strict TLS 1.2+/mTLS client options (`ca_file`, `cert_file`, `key_file`), `search`, `cases`, `update_case`, `verify_ledger`, `reload_policy`, and zero-dep pure-Python `verify_ledger_dir` verified bit-for-bit against Go ledger chains.

## [0.2.0] - 2026-11-27

### Added
- **6 Enterprise Telemetry Parsers + Bounded Gzip Ingestion (`internal/normalizer`)**: Added `auditd`, `cloudtrail` (single event and `Records` envelopes), `k8s-audit`, `suricata` EVE JSON, `win-evtx` JSON, and IBM `leef` (`v1.0`/`v2.0`) alongside transparent `64 MiB`-capped gzip decompression (13 total formats + `auto`).
- **Native Pure-Go Sigma YAML Engine (`internal/sigma`) & `SIEM-403`**: Compiles multi-document Sigma rules supporting wildcards, `|contains`, `|startswith`, `|endswith`, `|re`, `|cidr`, `|base64` (3-offset), `|all`, `|cased`, recursive boolean AST (`and`/`or`/`not`/`1 of`/`all of`), `logsource`, MITRE ATT&CK tags, and `timeframe` + `count(...) by ...` aggregations with fail-closed validation.
- **Ordered Multi-Step Sequence Correlation (`SIEM-206`)**: EQL-style ordered kill-chain progression (`sequence_rules` with >=2 steps inside bounded sliding windows) in `internal/policy` and `internal/correlator`.
- **STIX 2.1 / CIDR Threat Intel & Asset Criticality (`internal/intel`, `SIEM-502`)**: Loads STIX 2.1 JSON bundles, CSV, and plaintext IP/CIDR/domain lists (`SIEM-502`) plus YAML/JSON `AssetCatalog` (`tier1` automatically escalates matching incident severity by one level).
- **Syslog UDP/TCP Network Receiver (`internal/server/syslog.go`)**: Added bounded UDP (`64 KiB`) and TCP (`256 KiB` line, `128` max connections, `60s` idle timeout) RFC 3164/5424 listeners via `serve --syslog-udp` / `--syslog-tcp` with Prometheus counters.
- **11-Subcommand CLI & 10-Tool MCP Server**: Added `verify-sigma`, overlay flags (`--sigma`, `--threat-intel`, `--assets`), and MCP tools `siem_verify_sigma` + `siem_match_threat_intel`.
- **Python SDK v0.2.0 (`raksa-siem-sdk`)**: Parity upgrade adding all 13 log formats, bounded `.gz` `normalize_file`, stdlib `ThreatFeed` (STIX 2.1 + CIDR), `SequenceRule`, and `AssetCatalog`.

## [0.1.0] - 2026-11-27

### Added
- **Raksa Finding Schema v1 (`internal/schema`, `internal/report`)**: Canonical `layer: "siem"`, 20 cataloged `SIEM-*` rules (`SIEM-001`..`501`) with MITRE D3FEND mappings, 0-100 posture scoring (`A+`..`F`), SARIF 2.1.0/JSON/Table/Markdown/NDJSON export, and ANSI/UTF-8 terminal sanitization.
- **7-Format + Auto Log Normalizer (`internal/normalizer`)**: Supports `raksa`, `raksa-ndjson`, `auth`, `syslog`, `nginx`, `jsonl`, `cef`, and `auto` format inference.
- **Fail-Closed Policy & Detection-as-Code Engine (`internal/policy`)**: YAML/JSON `.raksa-siem.yml` discovery, custom regex/threshold rule compilation, time-bounded waiver expiry checks, HTTPS-or-localhost sink validation, and SHA-256 baseline gating.
- **20-Rule Stateful Cross-Layer Correlator (`internal/correlator`)**: Time-window correlation across authentication, web/network bursts, cross-layer IP/host pivots (`SIEM-201`..`205`), alert storms, log tampering, watchlists, and YAML custom rules plus timeline builder.
- **Alert Suppression Router, Multi-File Tailer & HTTP SIEM API (`internal/router`, `internal/tailer`, `internal/server`)**: Windowed alert deduplication, Webhook HMAC-SHA256 / Slack / Discord / Telegram / File sinks, `--dry-run`, file rotation recovery, Prometheus `/metrics`, `/healthz`, constant-time API key auth, and NDJSON store persistence.
- **10-Subcommand CLI & 8-Tool Stdio MCP Server (`cmd/raksa-siem`, `internal/mcp`)**: `analyze`, `correlate`, `normalize`, `watch`, `serve`, `verify-rules`, `test-alert`, `rules`, `mcp`, `version` plus bounded 2 MiB JSON-RPC 2.0 MCP tools.
- **Zero-Dependency Python SDK (`sdk/python`)**: Pure-stdlib `raksa-siem-sdk v0.1.0` with local normalizer, stateful correlator, posture calculator, timeline builder, and HTTPS-enforced `SiemClient`.
- **Container, CI & Release Packaging**: Multi-stage non-root distroless `Dockerfile` (`65532:65532`), Go race/vulncheck + Python 3.11-3.13 + Docker smoke CI workflow, and 6-OS static binary + Python wheel release workflow.
