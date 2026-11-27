"""Zero-dependency HTTP and mTLS client for the raksa-siem REST ingest & query server."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .normalizer import NormalizedEvent


class SiemClientError(RuntimeError):
    """Raised on validation failures, TLS config errors, or HTTP errors from raksa-siem serve."""


def validate_endpoint_url(url: str) -> str:
    cleaned = url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(cleaned)
    if not parsed.scheme or not parsed.netloc:
        raise SiemClientError(f"invalid endpoint URL {url!r}")
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https":
        return cleaned
    if parsed.scheme == "http" and host in ("127.0.0.1", "localhost", "::1"):
        return cleaned
    raise SiemClientError(
        f"insecure endpoint scheme {parsed.scheme!r} for host {host!r}; use HTTPS or localhost"
    )


class SiemClient:
    """Stdlib urllib client wrapping raksa-siem v0.3.0 REST, RBAC, and mTLS endpoints."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 10.0,
        ca_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
    ) -> None:
        self.base_url = validate_endpoint_url(base_url)
        self._api_key = api_key
        self.timeout = timeout
        if key_file and not cert_file:
            raise SiemClientError("key_file requires cert_file")

        self._ssl_ctx: ssl.SSLContext | None = None
        if self.base_url.startswith("https://") or ca_file or cert_file:
            try:
                ctx = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                if cert_file:
                    ctx.load_cert_chain(
                        certfile=str(cert_file),
                        keyfile=str(key_file) if key_file else None,
                    )
            except (OSError, ssl.SSLError) as exc:
                raise SiemClientError(f"TLS configuration error: {exc}") from None
            self._ssl_ctx = ctx

    def _request_json(self, method: str, path: str, payload: Any = None) -> Any:
        headers = {"Accept": "application/json", "User-Agent": "raksa-siem-sdk/0.3.0"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        data: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                raw = resp.read().decode("utf-8")
                ctype = resp.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    return json.loads(raw)
                return raw
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise SiemClientError(f"HTTP {exc.code} on {path}: {err_body}") from None
        except urllib.error.URLError as exc:
            raise SiemClientError(f"connection error on {path}: {exc.reason}") from None
        except OSError as exc:
            raise SiemClientError(f"transport error on {path}: {exc}") from None

    def healthz(self) -> dict[str, Any]:
        return self._request_json("GET", "/healthz")

    def metrics(self) -> str:
        return str(self._request_json("GET", "/metrics"))

    def ingest(
        self,
        items: list[NormalizedEvent] | list[str] | str | dict[str, Any],
        *,
        fmt: str = "auto",
    ) -> dict[str, Any]:
        body: Any
        if isinstance(items, str):
            body = {"format": fmt, "raw": items}
        elif isinstance(items, dict):
            body = items
        elif items and isinstance(items[0], NormalizedEvent):
            body = {"format": fmt, "events": [ev.to_dict() for ev in items]}  # type: ignore[union-attr]
        else:
            body = {"format": fmt, "lines": list(items)}

        q = urllib.parse.urlencode({"format": fmt})
        return self._request_json("POST", f"/api/v1/ingest?{q}", payload=body)

    def incidents(
        self,
        *,
        severity: str = "",
        rule_id: str = "",
        host: str = "",
        src_ip: str = "",
        limit: int = 200,
    ) -> dict[str, Any]:
        params = {k: v for k, v in {
            "severity": severity,
            "rule_id": rule_id,
            "host": host,
            "src_ip": src_ip,
            "limit": str(limit),
        }.items() if v}
        qs = urllib.parse.urlencode(params)
        return self._request_json("GET", f"/api/v1/incidents?{qs}")

    def posture(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/posture")

    def timeline(
        self,
        *,
        src_ip: str = "",
        host: str = "",
        user: str = "",
        layer: str = "",
        limit: int = 200,
    ) -> dict[str, Any]:
        params = {k: v for k, v in {
            "src_ip": src_ip,
            "host": host,
            "user": user,
            "layer": layer,
            "limit": str(limit),
        }.items() if v}
        qs = urllib.parse.urlencode(params)
        return self._request_json("GET", f"/api/v1/timeline?{qs}")

    def search(
        self,
        *,
        from_ts: str = "",
        to_ts: str = "",
        kind: str = "",
        query: str = "",
        severity: str = "",
        rule_id: str = "",
        layer: str = "",
        host: str = "",
        src_ip: str = "",
        user: str = "",
        limit: int = 200,
    ) -> dict[str, Any]:
        params = {k: v for k, v in {
            "from": from_ts,
            "to": to_ts,
            "kind": kind,
            "query": query,
            "severity": severity,
            "rule_id": rule_id,
            "layer": layer,
            "host": host,
            "src_ip": src_ip,
            "user": user,
            "limit": str(limit),
        }.items() if v}
        qs = urllib.parse.urlencode(params)
        path = f"/api/v1/search?{qs}" if qs else "/api/v1/search"
        return self._request_json("GET", path)

    def cases(self, *, status: str = "") -> dict[str, Any]:
        qs = urllib.parse.urlencode({"status": status}) if status else ""
        path = f"/api/v1/cases?{qs}" if qs else "/api/v1/cases"
        return self._request_json("GET", path)

    def update_case(
        self,
        finding_id: str,
        status: str,
        *,
        assignee: str = "",
        author: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            "/api/v1/cases",
            payload={
                "finding_id": finding_id,
                "status": status,
                "assignee": assignee,
                "author": author,
                "note": note,
            },
        )

    def verify_ledger(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/ledger/verify")

    def reload_policy(self, *, policy_path: str = "") -> dict[str, Any]:
        body: dict[str, Any] = {"policy_path": policy_path} if policy_path else {}
        return self._request_json("POST", "/api/v1/reload", payload=body)
