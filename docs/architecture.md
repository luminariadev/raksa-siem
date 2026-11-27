# Architecture Overview: `raksa-siem` (Layer 6)

`raksa-siem` is Layer 6 (`observability-siem`) of the Raksa Security Suite. It ingests heterogeneous host, cloud, container, network, and telemetry logs (plain or `.gz`) alongside upstream Layer 1-5 Finding Schema v1 reports (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`), normalizes them into canonical events, evaluates stateful built-in/custom/Sigma/sequence correlation rules enriched with STIX 2.1/CIDR threat intelligence and asset tiers, persists hash-chained audit segments and incident cases, computes 0-100 posture scores, and routes reliably retried alerts.

## Pipeline Data Flow

```text
  Inputs (Files / Dirs / .gz / Stdin / Tailer / HTTPS/mTLS /api/v1/ingest / Syslog UDP & TCP)
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
  internal/policy      --->  Fail-closed YAML rules, waivers, SHA-256 baseline, SIGHUP reload
    |
    +---> internal/ledger   --->  siem-YYYY-MM-DD.ndjson SHA-256 chain + Search + Case triage
    +---> internal/report   --->  Table / JSON / SARIF 2.1.0 / Markdown / NDJSON / HTML / ATT&CK Nav
    +---> internal/router   --->  Suppression + Retry/DLQ + Webhook(HMAC)/Slack/Discord/TG/Teams/PD/OG/File
    +---> internal/server   --->  HTTPS/mTLS + Scoped RBAC (/api/v1/*, /metrics, /healthz) + Syslog
    +---> internal/mcp      --->  12-tool stdio JSON-RPC 2.0 MCP server (2 MiB frame cap)
```

## Package Responsibilities

| Package | Responsibility |
| :--- | :--- |
| `internal/schema` | Raksa Schema v1 `Finding`, `Report`, `PostureScore`, `Event`, and 23-rule `RuleCatalog` (`SIEM-001`..`502`). |
| `internal/report` | 7 output renderers (`table`, `json`, `sarif`, `markdown`, `ndjson`, offline dark-mode SVG `html`, MITRE `attack-nav` v4.5) and terminal sanitization. |
| `internal/normalizer` | 13-format parser + `auto` + bounded `64 MiB` gzip decompression (`auditd`, `cloudtrail`, `k8s-audit`, `suricata`, `win-evtx`, `leef`, `auth`, `syslog`, `nginx`, `jsonl`, `cef`, Raksa Layer 1-5). |
| `internal/sigma` | Native pure-Go Sigma YAML compiler & AST evaluator (`contains`, `startswith`, `endswith`, `re`, `cidr`, `base64`, `all`, `cased`, `and`/`or`/`not`/`of`, piped `count() by`). |
| `internal/intel` | Zero-dep STIX 2.1 JSON, CSV, and plaintext CIDR/IP/domain threat intelligence engine plus YAML/JSON `AssetCatalog` tier-1 criticality escalation. |
| `internal/policy` | Fail-closed `.raksa-siem.yml` loader, custom rules, ordered `sequence_rules`, Sigma/TI/asset overlays, expiry-checked waivers, DLQ/retry bounds, sink URL verification, and SHA-256 baselines. |
| `internal/correlator` | Thread-safe sliding-window engine evaluating auth/web bursts, cross-layer pivots (`SIEM-201`..`205`), EQL-style sequences (`SIEM-206`), Sigma (`SIEM-403`), TI (`SIEM-502`), and asset tiering. |
| `internal/ledger` | Append-only date-segmented (`siem-YYYY-MM-DD.ndjson`) SHA-256 hash-chained audit ledger with retention pruning, historical search, case triage (`open`/`ack`/`resolved`/`false_positive`), and chain verification. |
| `internal/router` | Windowed `(rule_id, group_key)` suppression, exponential retry backoff (`0..5` retries), NDJSON DLQ + `ReplayDLQ`, and 8 sinks (`webhook` HMAC-SHA256, `slack`, `discord`, `telegram`, `teams`, `pagerduty`, `opsgenie`, `file`). |
| `internal/tailer` | Cross-platform poll-based file/directory tailer (`watch`) with partial-line buffering, rotation recovery, `--siem-out` NDJSON append, and `/metrics`. |
| `internal/server` | TLS 1.2+/mTLS and scoped constant-time RBAC REST API (`ingest`, `read`, `admin`), `SIGHUP` + `/api/v1/reload` atomic policy swap, ledger persistence/search/case endpoints, bounded Syslog UDP/TCP, and Prometheus `/metrics`. |
| `internal/mcp` | Stdio JSON-RPC 2.0 MCP server (`2 MiB` frame cap) exposing 12 tools including `siem_verify_ledger` and `siem_triage_case`. |
| `sdk/python` | Zero-dependency Python 3.11+ SDK (`raksa_siem_sdk v0.3.0`) with 13 formats, `.gz` loader, STIX/CIDR/sequence/asset parity, mTLS `SiemClient`, search/cases/reload APIs, and cross-language `verify_ledger_dir`. |

## Scope & Boundaries

- Persisted storage targets single-node local or attached volumes via date-segmented SHA-256 hash-chained NDJSON logs rather than a distributed multi-node search cluster or proprietary binary database.
- Case workflow state (`open`, `ack`, `resolved`, `false_positive`) is rebuilt deterministically by replaying immutable `case_update` ledger records alongside event and finding entries.
- Offline HTML graph exports embed all SVG geometry, styles, and vanilla filtering scripts inline to guarantee zero external network calls or CDN dependencies during incident triage.
