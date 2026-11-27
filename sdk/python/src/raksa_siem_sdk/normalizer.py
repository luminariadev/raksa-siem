"""Multi-format log and Raksa Finding Schema v1 normalizer."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SUPPORTED_FORMATS = (
    "auto",
    "raksa",
    "raksa-ndjson",
    "auth",
    "syslog",
    "nginx",
    "jsonl",
    "cef",
)

_NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
)
_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?:(?P<ts_iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<ts_bsd>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_.\-\/]+?)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
_IP_RE = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})\b")
_USER_FAILED_RE = re.compile(r"for\s+(?:invalid\s+user\s+)?([A-Za-z0-9_.\-]+)")
_WEB_PROBE_TOKENS = ("/.env", "wp-login", "../", "union select", "or 1=1", "/.git/", "etc/passwd", "<script")

_TOOL_LAYER_MAP = {
    "raksa-netguard": "network-defense",
    "raksa-hostguard": "host-hardening",
    "raksa-webshield": "web-defense",
    "raksa-pipeguard": "devsecops",
    "raksa-iocscan": "ioc-defense",
    "raksa-siem": "siem",
}


@dataclass
class NormalizedEvent:
    id: str
    timestamp: str
    source_format: str
    layer: str
    severity: str
    category: str
    action: str
    outcome: str
    message: str
    tool: str = ""
    rule_id: str = ""
    src_ip: str = ""
    host: str = ""
    user: str = ""
    process: str = ""
    http_method: str = ""
    http_path: str = ""
    http_status: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "timestamp": self.timestamp,
            "source_format": self.source_format,
            "layer": self.layer,
            "severity": self.severity,
            "category": self.category,
            "action": self.action,
            "outcome": self.outcome,
            "message": self.message,
        }
        for key in ("tool", "rule_id", "src_ip", "host", "user", "process", "http_method", "http_path"):
            val = getattr(self, key)
            if val:
                payload[key] = val
        if self.http_status > 0:
            payload["http_status"] = self.http_status
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


def detect_format(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return "jsonl"
    if stripped.startswith("CEF:"):
        return "cef"
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                if "findings" in obj and ("tool" in obj or "schema_version" in obj):
                    return "raksa"
                if "rule_id" in obj and ("severity" in obj or "layer" in obj):
                    return "raksa-ndjson"
                return "jsonl"
        except json.JSONDecodeError:
            return "jsonl"
    if _NGINX_RE.match(stripped):
        return "nginx"
    if any(tok in stripped for tok in ("sshd", "sudo", "useradd", "usermod", "su[", "pam_unix")):
        return "auth"
    return "syslog"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_syslog_ts(ts_iso: str | None, ts_bsd: str | None, default_year: int) -> str:
    if ts_iso:
        try:
            dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    if ts_bsd:
        normalized = " ".join(ts_bsd.split())
        try:
            dt = datetime.strptime(f"{default_year} {normalized}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    return _now_iso()


def _parse_nginx_ts(raw: str) -> str:
    try:
        dt = datetime.strptime(raw.strip(), "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return _now_iso()


def normalize_report(report_obj: dict[str, Any], source_name: str = "report.json") -> list[NormalizedEvent]:
    tool = str(report_obj.get("tool", "unknown"))
    layer = str(report_obj.get("layer") or _TOOL_LAYER_MAP.get(tool, "telemetry"))
    fallback_ts = str(report_obj.get("generated_at") or _now_iso())
    events: list[NormalizedEvent] = []
    for idx, f in enumerate(report_obj.get("findings") or []):
        if not isinstance(f, dict):
            continue
        ev_map = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        f_layer = str(f.get("layer") or layer)
        cat = f_layer if f_layer else "finding"
        if f_layer == "network-defense":
            cat = "network"
        elif f_layer == "web-defense":
            cat = "web"
        elif f_layer == "ioc-defense":
            cat = "malware"
        events.append(
            NormalizedEvent(
                id=str(f.get("id") or f"raksa-{idx}"),
                timestamp=str(f.get("timestamp") or fallback_ts),
                source_format="raksa",
                layer=f_layer,
                tool=tool,
                rule_id=str(f.get("rule_id") or ""),
                severity=str(f.get("severity") or "info").lower(),
                category=cat,
                action="finding",
                outcome="alert",
                src_ip=str(ev_map.get("src_ip") or ""),
                host=str(ev_map.get("host") or ""),
                user=str(ev_map.get("user") or ""),
                message=str(f.get("description") or f.get("title") or ""),
                metadata={"source": source_name, "target": f.get("target", "")},
            )
        )
    return events


def normalize_line(line: str, fmt: str = "auto", default_year: int | None = None, seq: int = 1) -> list[NormalizedEvent]:
    fmt = fmt.strip().lower() or "auto"
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported format {fmt!r}")
    raw = line.strip()
    if not raw:
        return []
    year = default_year or datetime.now(timezone.utc).year
    actual = detect_format(raw) if fmt == "auto" else fmt

    if actual == "raksa":
        obj = json.loads(raw)
        return normalize_report(obj)

    if actual == "raksa-ndjson":
        obj = json.loads(raw)
        return normalize_report({"tool": obj.get("tool", "raksa"), "layer": obj.get("layer", ""), "findings": [obj]})

    if actual == "nginx":
        m = _NGINX_RE.match(raw)
        if not m:
            return []
        status = int(m.group("status"))
        path = m.group("path")
        lower_path = path.lower()
        is_probe = any(tok in lower_path for tok in _WEB_PROBE_TOKENS)
        sev = "high" if status >= 500 or is_probe else ("medium" if status in (401, 403, 404) else "info")
        action = "probe" if is_probe else ("server_error" if status >= 500 else "request")
        outcome = "blocked" if status in (401, 403, 404) else ("error" if status >= 500 else "success")
        return [
            NormalizedEvent(
                id=f"nginx-{seq}",
                timestamp=_parse_nginx_ts(m.group("ts")),
                source_format="nginx",
                layer="web-defense",
                severity=sev,
                category="web",
                action=action,
                outcome=outcome,
                src_ip=m.group("ip"),
                http_method=m.group("method"),
                http_path=path,
                http_status=status,
                message=f'{m.group("method")} {path} -> {status}',
            )
        ]

    if actual in ("auth", "syslog"):
        m = _SYSLOG_RE.match(raw)
        if not m:
            return []
        msg = m.group("msg")
        lower_msg = msg.lower()
        proc = m.group("proc").lower()
        host = m.group("host")
        ts = _parse_syslog_ts(m.group("ts_iso"), m.group("ts_bsd"), year)
        ip_m = _IP_RE.search(msg)
        src_ip = ip_m.group(1) if ip_m else ""
        user_m = _USER_FAILED_RE.search(msg)
        user = user_m.group(1) if user_m else ""

        sev = "info"
        cat = "syslog"
        action = "log"
        outcome = "observed"
        if any(t in lower_msg for t in ("history -c", "shred ", "truncate -s 0", "/var/log/auth.log")):
            sev, cat, action = "high", "ops", "log_tamper"
        elif "new user" in lower_msg or "usermod" in lower_msg or "added to group" in lower_msg:
            sev, cat, action, outcome = "high", "privilege", "account_change", "success"
        elif "sudo" in proc or "su" == proc:
            cat, action = "privilege", "sudo"
            if "incorrect password" in lower_msg or "authentication failure" in lower_msg:
                sev, outcome = "medium", "failure"
            else:
                sev, outcome = "medium", "success"
        elif "failed password" in lower_msg or "authentication failure" in lower_msg or "invalid user" in lower_msg:
            sev, cat, action, outcome = "medium", "auth", "login", "failure"
        elif "accepted password" in lower_msg or "accepted publickey" in lower_msg:
            sev, cat, action, outcome = "info", "auth", "login", "success"

        return [
            NormalizedEvent(
                id=f"{actual}-{seq}",
                timestamp=ts,
                source_format=actual,
                layer="host-hardening",
                severity=sev,
                category=cat,
                action=action,
                outcome=outcome,
                src_ip=src_ip,
                host=host,
                user=user,
                process=proc,
                message=msg,
            )
        ]

    if actual == "jsonl":
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return []
        return [
            NormalizedEvent(
                id=str(obj.get("id") or f"jsonl-{seq}"),
                timestamp=str(obj.get("timestamp") or obj.get("ts") or _now_iso()),
                source_format="jsonl",
                layer=str(obj.get("layer") or "telemetry"),
                severity=str(obj.get("severity") or obj.get("level") or "info").lower(),
                category=str(obj.get("category") or "telemetry"),
                action=str(obj.get("action") or "event"),
                outcome=str(obj.get("outcome") or "observed"),
                src_ip=str(obj.get("src_ip") or obj.get("ip") or ""),
                host=str(obj.get("host") or ""),
                user=str(obj.get("user") or ""),
                message=str(obj.get("message") or obj.get("msg") or raw),
            )
        ]

    if actual == "cef":
        parts = raw.split("|", 7)
        if len(parts) < 8:
            return []
        ext_tokens = parts[7].split()
        ext: dict[str, str] = {}
        for tok in ext_tokens:
            if "=" in tok:
                k, v = tok.split("=", 1)
                ext[k] = v
        try:
            sev_num = int(parts[6])
        except ValueError:
            sev_num = 3
        sev = "critical" if sev_num >= 9 else ("high" if sev_num >= 7 else ("medium" if sev_num >= 4 else "low"))
        return [
            NormalizedEvent(
                id=f"cef-{seq}",
                timestamp=_now_iso(),
                source_format="cef",
                layer="siem",
                tool=parts[2],
                rule_id=parts[4],
                severity=sev,
                category="cef",
                action="alert",
                outcome=ext.get("outcome", "alert"),
                src_ip=ext.get("src", ""),
                host=ext.get("dhost", ""),
                user=ext.get("suser", ext.get("duser", "")),
                message=parts[5],
            )
        ]

    return []


def normalize_lines(lines: list[str] | str, fmt: str = "auto", default_year: int | None = None) -> list[NormalizedEvent]:
    if isinstance(lines, str):
        stripped = lines.strip()
        if (fmt == "raksa" or (fmt == "auto" and stripped.startswith("{"))) and stripped.endswith("}"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict) and "findings" in obj:
                    return normalize_report(obj)
            except json.JSONDecodeError:
                pass
        raw_lines = lines.splitlines()
    else:
        raw_lines = lines

    events: list[NormalizedEvent] = []
    for idx, line in enumerate(raw_lines, start=1):
        if not line.strip():
            continue
        try:
            events.extend(normalize_line(line, fmt=fmt, default_year=default_year, seq=idx))
        except (json.JSONDecodeError, ValueError):
            continue
    return events
