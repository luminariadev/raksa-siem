"""Multi-format log and Raksa Finding Schema v1 normalizer."""

from __future__ import annotations

import gzip
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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
    "auditd",
    "cloudtrail",
    "k8s-audit",
    "suricata",
    "win-evtx",
    "leef",
)

MAX_GZIP_EXPANDED_BYTES = 64 * 1024 * 1024

_NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
)
_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?:(?P<ts_iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<ts_bsd>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_.\-\/]+?)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
_AUDITD_HEADER_RE = re.compile(r"type=([A-Z0-9_]+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)$")
_AUDITD_KV_RE = re.compile(r'([A-Za-z0-9_\-]+)=("[^"]*"|\S+)')
_SUS_EXEC_RE = re.compile(r"(?i)(?:/dev/tcp|/bin/nc\b|curl_stage_probe|curl\s+.*\|\s*(?:ba)?sh|base64\s+-d|python3?\s+-c)")
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
    dst_ip: str = ""
    dst_port: int = 0
    host: str = ""
    user: str = ""
    process: str = ""
    path: str = ""
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
        for key in ("tool", "rule_id", "src_ip", "dst_ip", "host", "user", "process", "path", "http_method", "http_path"):
            val = getattr(self, key)
            if val:
                payload[key] = val
        if self.dst_port > 0:
            payload["dst_port"] = self.dst_port
        if self.http_status > 0:
            payload["http_status"] = self.http_status
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


def _detect_json_object_format(obj: dict[str, Any]) -> str:
    if "findings" in obj and ("tool" in obj or "schema_version" in obj):
        return "raksa"
    if "rule_id" in obj and ("severity" in obj or "layer" in obj) and "title" in obj:
        return "raksa-ndjson"
    if "Records" in obj or ("eventSource" in obj and "eventName" in obj):
        return "cloudtrail"
    if "verb" in obj and ("objectRef" in obj or "requestURI" in obj or obj.get("kind") == "Event"):
        return "k8s-audit"
    if "event_type" in obj and any(k in obj for k in ("alert", "dns", "http", "flow", "dest_ip")):
        return "suricata"
    if ("EventID" in obj or "event_id" in obj) and any(
        k in obj for k in ("Computer", "Channel", "ProviderName", "TargetUserName", "CommandLine", "EventData")
    ):
        return "win-evtx"
    return "jsonl"


def detect_format(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return "jsonl"
    if stripped.startswith("CEF:"):
        return "cef"
    if "LEEF:" in stripped:
        return "leef"
    if "msg=audit(" in stripped:
        return "auditd"
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                return _detect_json_object_format(obj)
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
                dst_ip=str(ev_map.get("dst_ip") or ""),
                dst_port=int(ev_map.get("dst_port") or ev_map.get("port") or 0),
                host=str(ev_map.get("host") or ""),
                user=str(ev_map.get("user") or ""),
                message=str(f.get("description") or f.get("title") or ""),
                metadata={"source": source_name, "target": f.get("target", ""), **{f"ev_{k}": v for k, v in ev_map.items()}},
            )
        )
    return events


def _normalize_cloudtrail_record(rec: dict[str, Any], seq: int) -> NormalizedEvent:
    ev_name = str(rec.get("eventName") or "")
    ev_src = str(rec.get("eventSource") or "")
    src_ip = str(rec.get("sourceIPAddress") or "")
    if ".amazonaws.com" in src_ip:
        src_ip = ""
    ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    user = str(ui.get("userName") or ui.get("arn") or ui.get("type") or "")
    region = str(rec.get("awsRegion") or "global")
    err_code = str(rec.get("errorCode") or "")
    low_name = ev_name.lower()

    sev, cat, action, outcome = "info", "cloud", ev_name or "cloud_api", "success"
    if err_code:
        outcome = "failure"
        if "denied" in err_code.lower() or "unauthorized" in err_code.lower():
            sev = "medium"
    if low_name in ("stoplogging", "deletetrail", "updatetrail", "deleteflowlogs"):
        sev, cat, action = "critical", "ops", "log_tamper"
    elif low_name == "consolelogin":
        cat, action = "auth", "login"
        resp = rec.get("responseElements") if isinstance(rec.get("responseElements"), dict) else {}
        if err_code or str(resp.get("ConsoleLogin") or "").lower() == "failure":
            sev, outcome = "medium", "failure"
    elif low_name in ("createaccesskey", "createuser", "attachuserpolicy", "attachrolepolicy", "putuserpolicy"):
        sev, cat, action = "high", "privilege", "account_change"

    return NormalizedEvent(
        id=str(rec.get("eventID") or rec.get("requestID") or f"ct-{seq}"),
        timestamp=str(rec.get("eventTime") or _now_iso()),
        source_format="cloudtrail",
        layer="cloud-audit",
        tool="aws-cloudtrail",
        rule_id=ev_name,
        severity=sev,
        category=cat,
        action=action,
        outcome=outcome,
        src_ip=src_ip,
        host=f"aws:{region}",
        user=user,
        message=f"CloudTrail {ev_src}/{ev_name} user={user or 'unknown'} outcome={outcome}",
        metadata={"event_name": ev_name, "event_source": ev_src, "aws_region": region},
    )


def _normalize_auditd(raw: str, seq: int) -> list[NormalizedEvent]:
    m = _AUDITD_HEADER_RE.search(raw)
    if not m:
        return []
    rec_type, epoch_str, seq_str, body = m.group(1), m.group(2), m.group(3), m.group(4)
    kv = {k.lower(): v.strip('"') for k, v in _AUDITD_KV_RE.findall(body)}
    try:
        dt = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
        ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        ts = _now_iso()

    host = kv.get("node") or kv.get("hostname") or kv.get("host") or ""
    user = kv.get("acct") or kv.get("auid") or kv.get("uid") or ""
    proc = kv.get("comm") or kv.get("exe") or ""
    src_ip = kv.get("addr") or ""
    if src_ip in ("?", "-"):
        src_ip = ""
    cmd_line = kv.get("proctitle") or kv.get("cmd") or body
    res = (kv.get("res") or "").lower()

    sev, cat, action, outcome = "info", "host", rec_type.lower(), ("failure" if res in ("failed", "fail") else "observed")
    if rec_type in ("USER_LOGIN", "USER_AUTH"):
        cat, action = "auth", "login"
        if outcome == "failure":
            sev = "medium"
    elif rec_type in ("ADD_USER", "DEL_USER", "ADD_GROUP", "USER_MGMT"):
        sev, cat, action = "high", "privilege", "account_change"
    elif rec_type in ("EXECVE", "SYSCALL"):
        cat, action = "process", "exec"
        if _SUS_EXEC_RE.search(cmd_line) or _SUS_EXEC_RE.search(body):
            sev = "high"

    return [
        NormalizedEvent(
            id=f"auditd-{seq_str}-{seq}",
            timestamp=ts,
            source_format="auditd",
            layer="host-hardening",
            tool="auditd",
            severity=sev,
            category=cat,
            action=action,
            outcome=outcome,
            src_ip=src_ip,
            host=host,
            user=user,
            process=proc,
            path=kv.get("exe") or kv.get("name") or "",
            message=f"auditd {rec_type}: {cmd_line}",
            metadata={"record_type": rec_type, "command_line": cmd_line},
        )
    ]


def _normalize_k8s_audit(obj: dict[str, Any], seq: int) -> NormalizedEvent:
    verb = str(obj.get("verb") or "").lower()
    uri = str(obj.get("requestURI") or "")
    u_map = obj.get("user") if isinstance(obj.get("user"), dict) else {}
    user = str(u_map.get("username") or u_map.get("uid") or "")
    ips = obj.get("sourceIPs") if isinstance(obj.get("sourceIPs"), list) else []
    src_ip = str(ips[0]) if ips else ""
    ref = obj.get("objectRef") if isinstance(obj.get("objectRef"), dict) else {}
    res = str(ref.get("resource") or "")
    sub = str(ref.get("subresource") or "")
    ns = str(ref.get("namespace") or "")
    full_res = f"{res}/{sub}" if sub else res
    rs = obj.get("responseStatus") if isinstance(obj.get("responseStatus"), dict) else {}
    status = int(rs.get("code") or 0)

    sev, cat, outcome = "info", "k8s", ("failure" if status >= 400 else "success")
    if status in (401, 403):
        sev = "medium"
    if full_res in ("pods/exec", "pods/attach") or res in ("clusterrolebindings", "secrets"):
        sev = "high"
        if res == "clusterrolebindings":
            cat = "privilege"

    return NormalizedEvent(
        id=str(obj.get("auditID") or f"k8s-{seq}"),
        timestamp=str(obj.get("requestReceivedTimestamp") or obj.get("stageTimestamp") or _now_iso()),
        source_format="k8s-audit",
        layer="cloud-audit",
        tool="kubernetes-audit",
        severity=sev,
        category=cat,
        action=verb or "audit",
        outcome=outcome,
        src_ip=src_ip,
        host=f"k8s:{ns}" if ns else "k8s-apiserver",
        user=user,
        path=full_res,
        http_method=verb.upper(),
        http_path=uri,
        http_status=status,
        message=f"k8s audit {verb} {full_res or uri} ns={ns or 'cluster'} status={status}",
        metadata={"k8s_verb": verb, "k8s_resource": full_res, "k8s_namespace": ns},
    )


def _normalize_suricata(obj: dict[str, Any], seq: int) -> NormalizedEvent:
    ev_type = str(obj.get("event_type") or "alert").lower()
    alert = obj.get("alert") if isinstance(obj.get("alert"), dict) else {}
    dns = obj.get("dns") if isinstance(obj.get("dns"), dict) else {}
    http = obj.get("http") if isinstance(obj.get("http"), dict) else {}

    domain = str(dns.get("rrname") or http.get("hostname") or "")
    sev, action, outcome, rule_id, msg = "info", ev_type, "observed", "", ""
    if alert:
        action = str(alert.get("action") or "alert")
        outcome = "alert"
        rule_id = str(alert.get("signature_id") or "")
        msg = str(alert.get("signature") or "")
        a_sev = int(alert.get("severity") or 3)
        sev = "critical" if a_sev == 1 else ("high" if a_sev == 2 else ("medium" if a_sev == 3 else "low"))
    if not msg:
        msg = f"DNS query: {domain}" if domain else f"Suricata {ev_type}"

    meta: dict[str, Any] = {"event_type": ev_type}
    if domain:
        meta["domain"] = domain

    return NormalizedEvent(
        id=f"suri-{seq}",
        timestamp=str(obj.get("timestamp") or _now_iso()),
        source_format="suricata",
        layer="network-defense",
        tool="suricata",
        rule_id=rule_id,
        severity=sev,
        category="network",
        action=action,
        outcome=outcome,
        src_ip=str(obj.get("src_ip") or ""),
        dst_ip=str(obj.get("dest_ip") or ""),
        dst_port=int(obj.get("dest_port") or 0),
        host=str(obj.get("host") or obj.get("sensor") or ""),
        http_method=str(http.get("http_method") or ""),
        http_path=str(http.get("url") or ""),
        http_status=int(http.get("status") or 0),
        message=msg,
        metadata=meta,
    )


def _normalize_win_evtx(obj: dict[str, Any], seq: int) -> NormalizedEvent:
    ev_id = int(obj.get("EventID") or obj.get("event_id") or 0)
    ev_data = obj.get("EventData") if isinstance(obj.get("EventData"), dict) else {}
    lookup = lambda *keys: next((str(d[k]) for d in (obj, ev_data) for k in keys if d.get(k) not in (None, "")), "")

    host = lookup("Computer", "Hostname", "host")
    user = lookup("TargetUserName", "SubjectUserName", "User", "user")
    src_ip = lookup("IpAddress", "SourceIp", "src_ip")
    if src_ip in ("-", "::1"):
        src_ip = ""
    proc = lookup("Image", "NewProcessName", "ProcessName", "process")
    cmd = lookup("CommandLine", "ParentCommandLine")

    sev, cat, action, outcome = "info", "host", f"event_{ev_id}", "observed"
    if ev_id == 4625:
        sev, cat, action, outcome = "medium", "auth", "login", "failure"
    elif ev_id == 4624:
        cat, action, outcome = "auth", "login", "success"
    elif ev_id in (4720, 4728, 4732, 4756):
        sev, cat, action, outcome = "high", "privilege", "account_change", "success"
    elif ev_id in (4688, 1):
        cat, action = "process", "exec"
        if _SUS_EXEC_RE.search(cmd):
            sev = "high"
    elif ev_id in (1102, 104):
        sev, cat, action = "critical", "ops", "log_tamper"

    return NormalizedEvent(
        id=f"evtx-{ev_id}-{seq}",
        timestamp=str(obj.get("TimeCreated") or obj.get("timestamp") or obj.get("@timestamp") or _now_iso()),
        source_format="win-evtx",
        layer="host-hardening",
        tool="windows-evtx",
        rule_id=str(ev_id),
        severity=sev,
        category=cat,
        action=action,
        outcome=outcome,
        src_ip=src_ip,
        host=host,
        user=user,
        process=proc,
        message=str(obj.get("Message") or obj.get("message") or f"WinEvent {ev_id} user={user or 'system'} cmd={cmd}").strip(),
        metadata={"event_id": str(ev_id), "command_line": cmd},
    )


def _normalize_leef(raw: str, seq: int) -> list[NormalizedEvent]:
    idx = raw.find("LEEF:")
    if idx < 0:
        return []
    parts = raw[idx:].split("|", 5)
    if len(parts) < 6:
        return []
    ver, vendor, product, _, ev_id, rest = parts
    sep, kv_raw = "\t", rest
    if ver.startswith("LEEF:2.") and "|" in rest:
        custom_sep, kv_raw = rest.split("|", 1)
        if custom_sep.startswith("0x"):
            try:
                sep = chr(int(custom_sep[2:], 16))
            except ValueError:
                pass
        elif custom_sep:
            sep = custom_sep

    tokens = kv_raw.split(sep) if sep in kv_raw else kv_raw.split()
    kv: dict[str, str] = {}
    for tok in tokens:
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k.strip()] = v.strip()

    try:
        sev_num = int(kv.get("sev") or kv.get("severity") or 6)
    except ValueError:
        sev_num = 6
    sev = "critical" if sev_num >= 10 else ("high" if sev_num >= 8 else ("medium" if sev_num >= 6 else "low"))
    return [
        NormalizedEvent(
            id=f"leef-{seq}",
            timestamp=str(kv.get("devTime") or _now_iso()),
            source_format="leef",
            layer=_TOOL_LAYER_MAP.get(product.lower(), "telemetry"),
            tool=product,
            rule_id=ev_id,
            severity=sev,
            category=kv.get("cat", "leef").lower(),
            action=kv.get("action", "alert").lower(),
            outcome=kv.get("outcome", "alert").lower(),
            src_ip=kv.get("src") or kv.get("srcIP") or "",
            dst_ip=kv.get("dst") or kv.get("dstIP") or "",
            dst_port=int(kv["dstPort"]) if kv.get("dstPort", "").isdigit() else 0,
            host=kv.get("devName") or kv.get("identHostName") or "",
            user=kv.get("usrName") or kv.get("suser") or "",
            message=kv.get("msg") or kv.get("reason") or ev_id,
            metadata={"leef_vendor": vendor, "leef_product": product},
        )
    ]


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
        return normalize_report(json.loads(raw))
    if actual == "raksa-ndjson":
        obj = json.loads(raw)
        return normalize_report({"tool": obj.get("tool", "raksa"), "layer": obj.get("layer", ""), "findings": [obj]})
    if actual == "cloudtrail":
        obj = json.loads(raw)
        if isinstance(obj.get("Records"), list):
            return [_normalize_cloudtrail_record(r, seq + i) for i, r in enumerate(obj["Records"]) if isinstance(r, dict)]
        return [_normalize_cloudtrail_record(obj, seq)]
    if actual == "k8s-audit":
        return [_normalize_k8s_audit(json.loads(raw), seq)]
    if actual == "suricata":
        return [_normalize_suricata(json.loads(raw), seq)]
    if actual == "win-evtx":
        return [_normalize_win_evtx(json.loads(raw), seq)]
    if actual == "auditd":
        return _normalize_auditd(raw, seq)
    if actual == "leef":
        return _normalize_leef(raw, seq)

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

        sev, cat, action, outcome = "info", "syslog", "log", "observed"
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
        if (fmt in ("raksa", "cloudtrail") or (fmt == "auto" and stripped.startswith("{"))) and stripped.endswith("}"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    if "findings" in obj:
                        return normalize_report(obj)
                    if isinstance(obj.get("Records"), list):
                        return [
                            _normalize_cloudtrail_record(r, i + 1)
                            for i, r in enumerate(obj["Records"])
                            if isinstance(r, dict)
                        ]
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


def normalize_file(path: str | Path, fmt: str = "auto", *, max_bytes: int = MAX_GZIP_EXPANDED_BYTES) -> list[NormalizedEvent]:
    """Read a plain or gzip-compressed telemetry file with a strict decompressed size limit."""
    raw = Path(path).read_bytes()
    if raw[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = gz.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"decompressed telemetry {path} exceeds {max_bytes} byte safety limit")
                chunks.append(chunk)
            raw = b"".join(chunks)
    elif len(raw) > max_bytes:
        raise ValueError(f"telemetry file {path} exceeds {max_bytes} byte limit")
    return normalize_lines(raw.decode("utf-8", errors="replace"), fmt=fmt)
