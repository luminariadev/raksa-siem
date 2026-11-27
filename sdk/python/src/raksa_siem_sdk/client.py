"""Zero-dependency HTTP client for the raksa-siem REST ingest & query server."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .normalizer import NormalizedEvent


class SiemClientError(RuntimeError):
    """Raised on validation failures or HTTP errors from raksa-siem serve."""


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
    """Stdlib urllib client wrapping raksa-siem REST API endpoints."""

    def __init__(self, base_url: str, *, api_key: str | None = None, timeout: float = 10.0) -> None:
        self.base_url = validate_endpoint_url(base_url)
        self._api_key = api_key
        self.timeout = timeout

    def _request_json(self, method: str, path: str, payload: Any = None) -> Any:
        headers = {"Accept": "application/json", "User-Agent": "raksa-siem-sdk/0.1.0"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        data: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
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
