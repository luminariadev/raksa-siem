# Architecture Overview: `raksa-siem` (Layer 6)

`raksa-siem` is Layer 6 (`observability-siem`) of the Raksa Security Suite. It ingests heterogeneous host, cloud, container, network, and telemetry logs (plain or `.gz`) alongside upstream Layer 1-5 Finding Schema v1 reports (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`), normalizes them into canonical events, evaluates stateful built-in/custom/Sigma/sequence correlation rules enriched with STIX 2.1/CIDR threat intelligence and asset tiers, computes 0-100 posture scores, and routes deduplicated alerts.

## Pipeline Data Flow

```text
  Inputs (Files / Dirs / .gz / Stdin / Tailer / HTTP /api/v1/ingest / Syslog UDP & TCP)
    |  13 Formats + auto: raksa, raksa-ndjson, auth, syslog, nginx, jsonl, cef,
    |                     auditd, cloudtrail, k8s-audit, suricata, win-evtx, leef
    v
  internal/normalizer  --->  Canonical schema.Event stream (with metadata)
    |
    v
  internal/correlator  --->  23 SIEM rules (SIEM-001..502) + Sequence + Sigma + Timeline
    |   +-- internal/sigma (native Sigma YAML AST & count() by aggregations)
    |   +-- internal/intel (STIX 2.1 / CIDR feeds + tier1 asset severity escalation)
    v
  internal/policy      --->  Fail-closed YAML rules, waivers, SHA-256 baseline
    |
    +---> internal/report   ---> Table / JSON / SARIF 2.1.0 / Markdown / NDJSON
    +---> internal/router   ---> Alert suppression + Webhook(HMAC)/Slack/Discord/TG/File
    +---> internal/server   ---> REST API (/api/v1/*, /metrics, /healthz) + Syslog UDP/TCP
    +---> internal/mcp      ---> 10-tool stdio JSON-RPC 2.0 MCP server (2 MiB frame cap)
```

## Package Responsibilities

| Package | Responsibility |
| :--- | :--- |
| `internal/schema` | Raksa Schema v1 `Finding`, `Report`, `PostureScore`, `Event`, and 23-rule `RuleCatalog` (`SIEM-001`..`502`). |
| `internal/report` | Output rendering (`table`, `json`, `sarif`, `markdown`, `ndjson`) and ANSI/UTF-8 terminal sanitization. |
| `internal/normalizer` | 13-format parser + `auto` + bounded `64 MiB` gzip decompression (`auditd`, `cloudtrail`, `k8s-audit`, `suricata`, `win-evtx`, `leef`, `auth`, `syslog`, `nginx`, `jsonl`, `cef`, Raksa Layer 1-5). |
| `internal/sigma` | Native pure-Go Sigma YAML compiler & AST evaluator (`contains`, `startswith`, `endswith`, `re`, `cidr`, `base64`, `all`, `cased`, `and`/`or`/`not`/`of`, piped `count() by`). |
| `internal/intel` | Zero-dep STIX 2.1 JSON, CSV, and plaintext CIDR/IP/domain threat intelligence engine plus YAML/JSON `AssetCatalog` tier-1 criticality escalation. |
| `internal/policy` | Fail-closed `.raksa-siem.yml` loader, custom rules, ordered `sequence_rules`, Sigma/TI/asset overlays, expiry-checked waivers, sink URL verification, and SHA-256 baselines. |
| `internal/correlator` | Thread-safe sliding-window engine evaluating auth/web bursts, cross-layer pivots (`SIEM-201`..`205`), EQL-style sequences (`SIEM-206`), Sigma (`SIEM-403`), TI (`SIEM-502`), and asset tiering. |
| `internal/router` | Windowed `(rule_id, group_key)` alert suppression and multi-sink delivery (`webhook` HMAC-SHA256, `slack`, `discord`, `telegram`, `file`, `--dry-run`). |
| `internal/tailer` | Cross-platform poll-based file/directory tailer (`watch`) with partial-line buffering, rotation recovery, `--siem-out` NDJSON append, and `/metrics`. |
| `internal/server` | Constant-time `X-API-Key` / Bearer REST API (`serve`) with `2 MiB` body cap, bounded Syslog UDP/TCP listeners, Prometheus `/metrics`, and NDJSON store persistence. |
| `internal/mcp` | Stdio JSON-RPC 2.0 MCP server (`2 MiB` frame cap) exposing 10 tools for AI/automation workflows. |
| `sdk/python` | Zero-dependency Python 3.11+ SDK (`raksa_siem_sdk v0.2.0`) with 13 formats, `.gz` loader, STIX/CIDR/sequence/asset parity, and `SiemClient`. |
