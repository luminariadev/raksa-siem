# raksa-siem

Layer 6 (`observability-siem`) of the **Raksa Security Suite**: a fast, single-binary security log normalizer, cross-layer correlator, continuous tailer, authenticated ingest server, MCP tool server, and zero-dependency Python SDK.

`raksa-siem` bridges host, network, web, DevSecOps, and IoC telemetry from upstream Raksa layers (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`) and standard operational logs into Raksa Finding Schema v1 incidents, timelines, SARIF 2.1.0 reports, Prometheus metrics, and alert routes.

## Highlights

- **7 Input Formats + Auto-Detection**: `raksa` (Layer 1-5 Finding JSON reports), `raksa-ndjson`, `auth` (SSH/sudo/PAM), `syslog`, `nginx` (combined/error logs), `jsonl`, and `cef`.
- **20 Built-In Rules (`SIEM-001`..`501`) + Detection-as-Code YAML**: Covers brute-force bursts, password spraying, compromise-after-failures, multi-IP logins, privilege changes, 4xx/5xx web probes, cross-layer IP/host correlation (`SIEM-201`..`205`), alert storms, log tampering, watchlists, and custom YAML regex/threshold rules.
- **Fail-Closed Policy & Baselines**: Waivers require both a non-empty `reason` and non-expired `expires_on`; webhook/Slack/Discord sinks require `https://` (or `localhost` / `127.0.0.1`); deterministic SHA-256 baseline gating supports clean CI gates.
- **Continuous Tailer & Authenticated Server**: `watch` handles partial lines, log truncation/rotation, and `/metrics`; `serve` exposes `/api/v1/ingest`, `/api/v1/incidents`, `/api/v1/posture`, `/api/v1/timeline`, `/metrics`, and `/healthz` with constant-time `X-API-Key` / `Authorization: Bearer` auth and NDJSON store persistence.
- **8-Tool Stdio MCP Server**: JSON-RPC 2.0 server (`raksa-siem mcp`) with `2 MiB` bounded frames for AI agent workflows (`siem_list_rules`, `siem_analyze_logs`, `siem_correlate_reports`, `siem_normalize_events`, `siem_build_timeline`, `siem_verify_rules`, `siem_check_suppression`, `siem_query_incidents`).
- **Minimal Dependency Footprint**: Go binary imports only `gopkg.in/yaml.v3 v3.0.1`; Python SDK (`raksa-siem-sdk v0.1.0`) uses 100% Python stdlib (`dependencies = []`).

## Quick Start

### Build & Verify Locally

```bash
git clone https://github.com/luminariadev/raksa-siem.git
cd raksa-siem
go build -ldflags="-s -w" -o raksa-siem ./cmd/raksa-siem
```

Run clean vs multi-layer attack-chain fixtures:

```bash
# Clean baseline telemetry -> exit 0, Posture 100/100 (A+)
./raksa-siem analyze testdata/clean --fail-on high --output table

# Multi-layer attack chain (auth + nginx + netguard + pipeguard + iocscan) -> exit 1
./raksa-siem analyze testdata/attack_chain --fail-on high --output sarif > siem.sarif

# Correlate upstream Raksa Finding JSON reports directly
./raksa-siem correlate testdata/attack_chain/raksa_*.json --output json

# Validate Detection-as-Code YAML policy and simulate alert delivery
./raksa-siem verify-rules examples/raksa-siem.yml examples/custom-rules.yml
./raksa-siem test-alert --policy examples/raksa-siem.yml --dry-run
```

## CLI Subcommands (10)

| Subcommand | Purpose |
| :--- | :--- |
| `analyze` | Normalize logs/reports, run 20-rule correlator, apply policy/baseline, exit `0`/`1`/`2`. |
| `correlate` | Correlate upstream Layer 1-5 Raksa JSON/NDJSON reports across IP and host boundaries. |
| `normalize` | Convert raw multi-format telemetry into canonical `schema.Event` JSON or `--ndjson`. |
| `watch` | Tail log files/directories continuously with rotation recovery, `--siem-out`, and `/metrics`. |
| `serve` | Run authenticated HTTP SIEM ingest and incident query API (`--api-key-env`, `--store`). |
| `verify-rules` | Fail-closed YAML/JSON policy, regex custom rule, waiver, and sink URL validation. |
| `test-alert` | Dispatch a synthetic alert (`--dry-run` by default) to test configured sinks and HMAC signing. |
| `rules` | List built-in `SIEM-001`..`501` rules (`--module` and `--output table|json`). |
| `mcp` | Launch the 8-tool stdio JSON-RPC 2.0 MCP server. |
| `version` | Print binary version, Raksa Schema version (`1.0`), and layer (`siem`). |

## Exit Codes

- `0`: Completed with no remaining findings meeting `--fail-on` (default `high`).
- `1`: One or more correlated incidents met or exceeded `--fail-on`.
- `2`: Invalid usage, fail-closed policy/validation error, or runtime failure.

## Python SDK (`raksa-siem-sdk`)

```bash
pip install ./sdk/python
```

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

## Benchmarks & Footprint (Measured on Windows amd64)

| Metric | Measured Result |
| :--- | :--- |
| Static Go Binary (`-ldflags="-s -w"`) | `7,788,544` bytes (`7.43 MiB`), `1` external module (`gopkg.in/yaml.v3 v3.0.1`) |
| `BenchmarkNormalizeMixed-12` | `9.82 ms` (`9,823,363 ns/op`, `3,544,538 B/op`, `33,050 allocs/op`) |
| `BenchmarkCorrelateEvents-12` (1,000 events) | `0.46 ms` (`464,767 ns/op`, `1,537,986 B/op`, `54 allocs/op`) |
| MCP stdio 51-frame burst (`initialize` + 50 calls) | `18.19 ms` total (`0.364 ms/call`) |
| Python SDK (`1,000` nginx normalize + correlate) | `20.04 ms` (`0` external deps) |
| Python SDK Wheel (`raksa_siem_sdk-0.1.0-py3-none-any.whl`) | `10,429` bytes |

## Documentation & Examples

- [Architecture Overview](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Changelog](CHANGELOG.md)
- [Example Policy](examples/raksa-siem.yml) & [Custom Detection Rules](examples/custom-rules.yml)

## License

MIT License. See [LICENSE](LICENSE).
