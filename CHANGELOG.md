# Changelog

All notable changes to `raksa-siem` are documented in this file.

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
