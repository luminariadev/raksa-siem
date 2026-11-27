# Threat Model: `raksa-siem` v0.1.0

This document captures trust boundaries, attacker capabilities considered, and implemented fail-closed controls in `raksa-siem`.

## Trust Boundaries

1. **Untrusted Log & Telemetry Inputs**: Log files, tailed streams, and HTTP `/api/v1/ingest` payloads frequently contain attacker-controlled HTTP paths, user strings, hostnames, and error messages.
   - *Control*: Terminal and table formatters pass strings through `report.SanitizeTerminal` (stripping ANSI escape sequences, C0/C1 control codes, and invalid UTF-8 sequences). HTTP ingest caps bodies at `2 MiB` via `http.MaxBytesReader`. JSONL, CSV/CEF, and regex paths handle malformed inputs without panics.
2. **Policy & Detection-as-Code Configuration (`.raksa-siem.yml`)**: Misconfigured waivers, expired suppressions, invalid regexes, or plain HTTP external webhook URLs could silently blind detection or leak incident metadata.
   - *Control*: `policy.ValidateAndCompile()` fails closed on invalid regex syntax, missing waiver `reason` or `expires_on`, expired waivers (`YYYY-MM-DD`), invalid thresholds, or unsupported sink schemes (`ValidateHTTPSOrLocalhostURL` allows only `https://` remotely or `http://127.0.0.1|localhost|::1` for local testing).
3. **HTTP Ingest Server (`raksa-siem serve`)**: Exposed on network interfaces to receive events and answer incident queries.
   - *Control*: Slowloris-hardened server timeouts (`ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `WriteTimeout: 15s`, `IdleTimeout: 60s`). When `--api-key-env` is specified and empty/unset, server startup fails closed rather than silently disabling auth. API key checks use constant-time `crypto/subtle.ConstantTimeCompare`.
4. **Alert Sinks & Secret Handling**: Webhook HMAC keys and Telegram bot tokens must never reside in configuration literals or leak via error messages.
   - *Control*: Policies reference environment variable names (`secret_env`, `token_env`) only. HTTP client errors redact `/bot<token>` path segments, and `raksa-pipeguard scan-secrets` verifies zero hardcoded credentials.
5. **Memory Exhaustion & State Unboundedness**: High-volume brute force or high-cardinality IP streams could exhaust correlator maps.
   - *Control*:Sliding windows prune expired entries on ingestion, `pruneMapsIfNeeded` caps state map growth, and HTTP `Server` bounds retained event (`50,000`) and incident (`10,000`) slices by default.
6. **Container & Supply Chain Footprint**: Minimize transitive attack surface inside CI/container runtime.
   - *Control*: Go module relies on a single external dependency (`gopkg.in/yaml.v3 v3.0.1`); Python SDK has zero runtime dependencies (`dependencies = []`); `Dockerfile` builds a static `CGO_ENABLED=0` binary into `gcr.io/distroless/static-debian12:nonroot` running as `65532:65532`.
