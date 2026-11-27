# Architecture Overview: `raksa-siem` (Layer 6)

`raksa-siem` is Layer 6 (`observability-siem`) of the Raksa Security Suite. It ingests heterogeneous host/web/telemetry logs alongside upstream Layer 1-5 Finding Schema v1 reports (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`), normalizes them into canonical events, runs stateful cross-layer time-window correlation, computes 0-100 posture scores, and routes deduplicated alerts.

## Pipeline Data Flow

```text
  Inputs (Files / Directories / Stdin / Tailer / HTTP POST /api/v1/ingest)
    |  Formats: raksa, raksa-ndjson, auth, syslog, nginx, jsonl, cef, auto
    v
  internal/normalizer  --->  Canonical schema.Event stream (with metadata)
    |
    v
  internal/correlator  --->  20 stateful SIEM rules (SIEM-001..501) + Timeline
    |                         (bounded sliding windows & cooldown state maps)
    v
  internal/policy      --->  Fail-closed YAML rules, waivers, SHA-256 baseline
    |
    +---> internal/report   ---> Table / JSON / SARIF 2.1.0 / Markdown / NDJSON
    +---> internal/router   ---> Alert suppression + Webhook(HMAC)/Slack/Discord/TG/File
    +---> internal/server   ---> REST API (/api/v1/*, /metrics, /healthz) + NDJSON store
    +---> internal/mcp      ---> 8-tool stdio JSON-RPC 2.0 MCP server (2 MiB frame cap)
```

## Package Responsibilities

| Package | Responsibility |
| :--- | :--- |
| `internal/schema` | Raksa Schema v1 `Finding`, `Report`, `PostureScore`, `Event`, and 20-rule `RuleCatalog` (`SIEM-001`..`501`). |
| `internal/report` | Output rendering (`table`, `json`, `sarif`, `markdown`, `ndjson`) and ANSI/UTF-8 terminal sanitization. |
| `internal/normalizer` | 7-format parser plus `auto` detector covering BSD/RFC3339 syslog, SSH/sudo auth, Nginx/Combined access logs, JSONL, CEF, and Raksa Layer 1-5 reports. |
| `internal/policy` | Fail-closed `.raksa-siem.yml` loader, regex compilation for Detection-as-Code rules, expiry-checked waivers, sink URL verification, and SHA-256 baseline matching. |
| `internal/correlator` | Thread-safe sliding-window engine evaluating auth brute force, web error/exploit bursts, cross-layer pivot rules (`SIEM-201`..`205`), ops integrity, watchlists, and custom YAML rules. |
| `internal/router` | Windowed `(rule_id, group_key)` alert suppression and multi-sink delivery (`webhook` with optional HMAC-SHA256 `X-Raksa-Signature`, `slack`, `discord`, `telegram`, `file`, `--dry-run`). |
| `internal/tailer` | Cross-platform poll-based file/directory tailer (`watch`) with partial-line buffering, truncation/rotation offset reset, `--siem-out` NDJSON append, and `/metrics` exposition. |
| `internal/server` | Constant-time `X-API-Key` / `Authorization: Bearer` REST ingest and query server (`serve`) with `2 MiB` body cap, HTTP header timeouts, and optional NDJSON persistence. |
| `internal/mcp` | Stdio JSON-RPC 2.0 MCP server (`2 MiB` frame cap) exposing 8 tools for AI/automation workflows. |
| `sdk/python` | Zero-dependency Python 3.11+ SDK (`raksa_siem_sdk`) mirroring log normalization, local correlation, timeline building, and HTTP `SiemClient`. |
