"""In-process SIEM correlation engine, timeline builder, and posture calculator."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .normalizer import NormalizedEvent

_SEV_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_SEV_PENALTY = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}


@dataclass
class Finding:
    id: str
    rule_id: str
    module: str
    layer: str
    severity: str
    title: str
    description: str
    target: str
    mitre_d3fend: str
    timestamp: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class PostureScore:
    score: int
    grade: str


@dataclass
class Timeline:
    total_events: int
    by_layer: dict[str, int]
    by_src_ip: dict[str, int]
    by_host: dict[str, int]
    entries: list[NormalizedEvent]


def compute_posture(findings: list[Finding]) -> PostureScore:
    score = 100
    for f in findings:
        score -= _SEV_PENALTY.get(f.severity.lower(), 0)
    if score < 0:
        score = 0
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return PostureScore(score=score, grade=grade)


def _parse_ts(raw: str) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def build_timeline(
    events: list[NormalizedEvent],
    *,
    src_ip: str = "",
    host: str = "",
    user: str = "",
    layer: str = "",
    limit: int = 200,
) -> Timeline:
    by_layer: dict[str, int] = defaultdict(int)
    by_ip: dict[str, int] = defaultdict(int)
    by_host: dict[str, int] = defaultdict(int)
    filtered: list[NormalizedEvent] = []

    for ev in events:
        if src_ip and ev.src_ip != src_ip:
            continue
        if host and ev.host.lower() != host.lower():
            continue
        if user and ev.user.lower() != user.lower():
            continue
        if layer and ev.layer.lower() != layer.lower():
            continue
        filtered.append(ev)
        if ev.layer:
            by_layer[ev.layer] += 1
        if ev.src_ip:
            by_ip[ev.src_ip] += 1
        if ev.host:
            by_host[ev.host] += 1

    filtered.sort(key=lambda e: (_parse_ts(e.timestamp), e.id))
    if limit > 0 and len(filtered) > limit:
        filtered = filtered[-limit:]

    return Timeline(
        total_events=len(filtered),
        by_layer=dict(by_layer),
        by_src_ip=dict(by_ip),
        by_host=dict(by_host),
        entries=filtered,
    )


class Correlator:
    """Zero-dependency stateful SIEM correlator matching raksa-siem core rules."""

    def __init__(
        self,
        *,
        auth_burst_threshold: int = 5,
        web_probe_threshold: int = 5,
        alert_storm_threshold: int = 10,
        watched_ips: list[str] | None = None,
        watched_hosts: list[str] | None = None,
        watched_users: list[str] | None = None,
    ) -> None:
        self.auth_burst_threshold = max(1, auth_burst_threshold)
        self.web_probe_threshold = max(1, web_probe_threshold)
        self.alert_storm_threshold = max(1, alert_storm_threshold)
        self.watched_ips = set(watched_ips or [])
        self.watched_hosts = {h.lower() for h in (watched_hosts or [])}
        self.watched_users = {u.lower() for u in (watched_users or [])}

        self._auth_fails_ip: dict[str, list[datetime]] = defaultdict(list)
        self._web_errs_ip: dict[str, list[datetime]] = defaultdict(list)
        self._layers_ip: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        self._layers_host: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        self._high_alerts: list[datetime] = []
        self._cooldown: dict[str, datetime] = {}
        self._seq = 0

    def _can_emit(self, rule_id: str, group_key: str, ts: datetime, window: timedelta) -> bool:
        key = f"{rule_id}|{group_key}"
        prev = self._cooldown.get(key)
        if prev is not None and (ts - prev) < window:
            return False
        self._cooldown[key] = ts
        return True

    def _emit(
        self,
        rule_id: str,
        module: str,
        severity: str,
        title: str,
        target: str,
        d3fend: str,
        ts: datetime,
        description: str,
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        self._seq += 1
        return Finding(
            id=f"{rule_id}-{self._seq}",
            rule_id=rule_id,
            module=module,
            layer="siem",
            severity=severity,
            title=title,
            description=description,
            target=target,
            mitre_d3fend=d3fend,
            timestamp=ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            evidence=evidence or {},
        )

    def ingest(self, ev: NormalizedEvent) -> list[Finding]:
        ts = _parse_ts(ev.timestamp)
        ts_str = ts
        out: list[Finding] = []

        if ev.category == "auth":
            if ev.outcome == "failure" and ev.src_ip:
                win10 = timedelta(minutes=10)
                win15 = timedelta(minutes=15)
                times = [t for t in self._auth_fails_ip[ev.src_ip] if ts_str - t <= win15]
                times.append(ts_str)
                self._auth_fails_ip[ev.src_ip] = times
                recent = [t for t in times if ts_str - t <= win10]
                if len(recent) >= self.auth_burst_threshold and self._can_emit("SIEM-001", ev.src_ip, ts, win10):
                    out.append(
                        self._emit(
                            "SIEM-001",
                            "auth",
                            "high",
                            "Authentication brute-force burst detected",
                            f"ip://{ev.src_ip}",
                            "D3-UAL",
                            ts,
                            f"{len(recent)} failed authentication attempts from {ev.src_ip} within 10m.",
                            {"src_ip": ev.src_ip, "failures": len(recent)},
                        )
                    )
            elif ev.outcome == "success" and ev.src_ip:
                win15 = timedelta(minutes=15)
                prior = [t for t in self._auth_fails_ip.get(ev.src_ip, []) if ts_str - t <= win15]
                if len(prior) >= 3 and self._can_emit("SIEM-002", ev.src_ip, ts, win15):
                    out.append(
                        self._emit(
                            "SIEM-002",
                            "auth",
                            "critical",
                            "Suspicious login success after failures",
                            f"ip://{ev.src_ip}",
                            "D3-IAM",
                            ts,
                            f"Source {ev.src_ip} authenticated successfully after {len(prior)} failed attempts.",
                            {"src_ip": ev.src_ip, "user": ev.user, "prior_failures": len(prior)},
                        )
                    )

        if ev.category == "web" and ev.src_ip and ev.http_status in (401, 403, 404):
            win5 = timedelta(minutes=5)
            w_times = [t for t in self._web_errs_ip[ev.src_ip] if ts_str - t <= win5]
            w_times.append(ts_str)
            self._web_errs_ip[ev.src_ip] = w_times
            if len(w_times) >= self.web_probe_threshold and self._can_emit("SIEM-101", ev.src_ip, ts, win5):
                out.append(
                    self._emit(
                        "SIEM-101",
                        "web-net",
                        "medium",
                        "HTTP 401/403/404 scan burst detected",
                        f"ip://{ev.src_ip}",
                        "D3-NTA",
                        ts,
                        f"Source {ev.src_ip} triggered {len(w_times)} client error responses within 5m.",
                        {"src_ip": ev.src_ip, "count": len(w_times)},
                    )
                )

        if ev.src_ip and ev.src_ip in self.watched_ips and self._can_emit("SIEM-501", f"ip:{ev.src_ip}", ts, timedelta(minutes=10)):
            out.append(
                self._emit(
                    "SIEM-501",
                    "watchlist",
                    "high",
                    "Watchlisted entity matched telemetry",
                    f"ip://{ev.src_ip}",
                    "D3-DEN",
                    ts,
                    f"Watchlisted IP {ev.src_ip} observed in {ev.layer}.",
                    {"src_ip": ev.src_ip},
                )
            )

        is_suspicious = _SEV_RANK.get(ev.severity, 1) >= 2 or ev.outcome in ("failure", "blocked", "alert") or ev.action in ("probe", "log_tamper", "finding")
        if is_suspicious and ev.src_ip:
            win30 = timedelta(minutes=30)
            recs = [(t, l) for t, l in self._layers_ip[ev.src_ip] if ts_str - t <= win30]
            recs.append((ts_str, ev.layer))
            self._layers_ip[ev.src_ip] = recs
            distinct_layers = sorted({l for _, l in recs if l})
            if len(distinct_layers) >= 2 and self._can_emit("SIEM-201", ev.src_ip, ts, win30):
                out.append(
                    self._emit(
                        "SIEM-201",
                        "cross-layer",
                        "high",
                        "Single source IP active across multiple Raksa layers",
                        f"ip://{ev.src_ip}",
                        "D3-CA",
                        ts,
                        f"Source IP {ev.src_ip} correlated across {len(distinct_layers)} layers: {', '.join(distinct_layers)}.",
                        {"src_ip": ev.src_ip, "layers": distinct_layers},
                    )
                )

        if is_suspicious and ev.host:
            win30 = timedelta(minutes=30)
            host_key = ev.host.lower()
            h_recs = [(t, l) for t, l in self._layers_host[host_key] if ts_str - t <= win30]
            h_recs.append((ts_str, ev.layer))
            self._layers_host[host_key] = h_recs
            h_layers = {l for _, l in h_recs if l}
            if "ioc-defense" in h_layers and ("network-defense" in h_layers or "host-hardening" in h_layers):
                if self._can_emit("SIEM-205", host_key, ts, win30):
                    out.append(
                        self._emit(
                            "SIEM-205",
                            "cross-layer",
                            "critical",
                            "Malware/IoC hit paired with runtime host or network alert",
                            f"host://{ev.host}",
                            "D3-ER",
                            ts,
                            f"Host {ev.host} correlates ioc-defense findings with runtime defense alerts.",
                            {"host": ev.host, "layers": sorted(h_layers)},
                        )
                    )

        return out

    def analyze_batch(self, events: list[NormalizedEvent]) -> tuple[list[Finding], Timeline]:
        ordered = sorted(events, key=lambda e: (_parse_ts(e.timestamp), e.id))
        findings: list[Finding] = []
        for ev in ordered:
            findings.extend(self.ingest(ev))
        return findings, build_timeline(ordered)
