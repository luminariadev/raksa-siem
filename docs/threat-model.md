# Threat Model: `raksa-siem` v0.2.0

This document captures trust boundaries, attacker capabilities considered, and implemented fail-closed controls in `raksa-siem`.

## Trust Boundaries

1. **Untrusted Log, Gzip & Network Telemetry Inputs**: Log files, `.gz` archives, tailed streams, Syslog UDP/TCP datagrams/connections, and HTTP `/api/v1/ingest` payloads frequently carry attacker-controlled paths, user names, hosts, and payloads.
   - *Control*: Terminal and table formatters pass strings through `report.SanitizeTerminal` (stripping ANSI escape sequences, C0/C1 control codes, and invalid UTF-8 sequences). Decompression in both Go and Python enforces a strict `64 MiB` expanded byte cap (`decompressIfGzip` / `normalize_file`) to block gzip bombs. HTTP ingest caps bodies at `2 MiB`; Syslog UDP caps datagrams at `64 KiB`, and Syslog TCP bounds line length (`256 KiB`), concurrent connections (`128`), and per-read idle deadlines (`60s`).
2. **Policy, Sigma YAML & Detection-as-Code Config**: Misconfigured waivers, expired suppressions, invalid regexes/CIDRs, malformed Sigma AST conditions, or plain HTTP external webhook URLs could silently blind detection or leak incident metadata.
   - *Control*: `policy.ValidateAndCompile()` and `sigma.ParseBytes()` fail closed on invalid regex syntax, invalid CIDRs, unknown Sigma selection identifiers, `<2` sequence steps, missing waiver `reason` or `expires_on`, expired waivers (`YYYY-MM-DD`), or unsupported sink schemes (`ValidateHTTPSOrLocalhostURL` allows only `https://` remotely or `http://127.0.0.1|localhost|::1` for local testing).
3. **HTTP Ingest & Query Server (`raksa-siem serve`)**: Exposed on network interfaces to ingest telemetry and answer incident queries.
   - *Control*: Slowloris-hardened timeouts (`ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `WriteTimeout: 15s`, `IdleTimeout: 60s`). When `--api-key-env` is specified and empty/unset, server startup fails closed rather than silently disabling auth. API key checks use constant-time `crypto/subtle.ConstantTimeCompare`.
4. **Alert Sinks & Secret Handling**: Webhook HMAC keys and Telegram bot tokens must never reside in configuration literals or leak via error messages.
   - *Control*: Policies reference environment variable names (`secret_env`, `token_env`) only. HTTP client errors redact `/bot<token>` path segments, and `raksa-pipeguard scan-secrets` verifies zero hardcoded credentials.
5. **Memory Exhaustion & State Unboundedness**: High-volume brute force, sequence chains, or high-cardinality IP streams could exhaust correlator maps.
   - *Control*: Sliding windows prune expired entries on ingestion, partial sequence chains cap at `32` per group key, `pruneMapsIfNeeded` bounds state map growth, and HTTP `Server` caps retained event (`50,000`) and incident (`10,000`) slices by default.
6. **Container & Supply Chain Footprint**: Minimize transitive attack surface inside CI and container runtimes.
   - *Control*: Go module relies on a single external dependency (`gopkg.in/yaml.v3 v3.0.1`); Python SDK has zero runtime dependencies (`dependencies = []`); `Dockerfile` builds a static `CGO_ENABLED=0` binary into `gcr.io/distroless/static-debian12:nonroot` running as `65532:65532` with `HEALTHCHECK`.
