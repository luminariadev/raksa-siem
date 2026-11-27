"""In-process SIEM correlation engine, threat intel matcher, sequence rules, and posture calculator."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .normalizer import NormalizedEvent

_SEV_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_SEV_PENALTY = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}
_STIX_PATTERN_RE = re.compile(r"\[([a-z0-9\-:.'_]+)\s*=\s*'([^']+)'\]", re.IGNORECASE)


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


@dataclass
class ThreatMatch:
    value: str
    kind: str
    severity: str
    source: str
    matched_on: str
    matched_val: str


class ThreatFeed:
    """Zero-dependency STIX 2.1, CIDR/IP plaintext, and CSV threat intel matcher."""

    def __init__(self) -> None:
        self._ips: dict[str, tuple[str, str]] = {}
        self._cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str, str]] = []
        self._domains: dict[str, tuple[str, str]] = {}
        self._users: dict[str, tuple[str, str]] = {}
        self.count = 0

    def add_indicator(self, value: str, *, kind: str = "", severity: str = "high", source: str = "feed") -> None:
        val = value.strip()
        if not val:
            return
        k = kind.strip().lower()
        if not k:
            if "/" in val:
                k = "cidr"
            else:
                try:
                    ipaddress.ip_address(val)
                    k = "ip"
                except ValueError:
                    k = "domain"

        if k == "ip":
            norm = str(ipaddress.ip_address(val))
            self._ips[norm] = (severity.lower(), source)
        elif k == "cidr":
            net = ipaddress.ip_network(val, strict=False)
            self._cidrs.append((net, val, severity.lower(), source))
        elif k == "domain":
            self._domains[val.lower()] = (severity.lower(), source)
        elif k == "user":
            self._users[val.lower()] = (severity.lower(), source)
        else:
            raise ValueError(f"unsupported threat indicator kind {k!r}")
        self.count += 1

    def load_file(self, path: str | Path) -> None:
        p = Path(path)
        raw = p.read_text(encoding="utf-8").strip()
        if not raw:
            return
        if p.suffix.lower() == ".json" or raw.startswith("{"):
            bundle = json.loads(raw)
            for obj in bundle.get("objects") or []:
                if str(obj.get("type") or "").lower() != "indicator":
                    continue
                conf = int(obj.get("confidence") or 50)
                sev = "critical" if conf >= 85 else "high"
                for lhs, val in _STIX_PATTERN_RE.findall(str(obj.get("pattern") or "")):
                    low_lhs = lhs.lower()
                    if low_lhs.startswith(("ipv4-addr", "ipv6-addr")):
                        self.add_indicator(val, kind=("cidr" if "/" in val else "ip"), severity=sev, source=f"stix:{p.name}")
                    elif low_lhs.startswith("domain-name"):
                        self.add_indicator(val, kind="domain", severity=sev, source=f"stix:{p.name}")
                    elif low_lhs.startswith("user-account"):
                        self.add_indicator(val, kind="user", severity=sev, source=f"stix:{p.name}")
            return

        for line in raw.splitlines():
            clean = line.split("#", 1)[0].strip()
            if clean:
                self.add_indicator(clean, source=p.name)

    def match_event(self, ev: NormalizedEvent) -> list[ThreatMatch]:
        hits: list[ThreatMatch] = []
        for field_name, ip_str in (("src_ip", ev.src_ip), ("dst_ip", ev.dst_ip)):
            if not ip_str:
                continue
            try:
                addr = ipaddress.ip_address(ip_str.strip())
            except ValueError:
                continue
            norm = str(addr)
            if norm in self._ips:
                sev, src = self._ips[norm]
                hits.append(ThreatMatch(norm, "ip", sev, src, field_name, norm))
            for net, raw_cidr, sev, src in self._cidrs:
                if addr.version == net.version and addr in net:
                    hits.append(ThreatMatch(raw_cidr, "cidr", sev, src, field_name, norm))

        if ev.user and ev.user.lower() in self._users:
            sev, src = self._users[ev.user.lower()]
            hits.append(ThreatMatch(ev.user, "user", sev, src, "user", ev.user))

        if self._domains:
            hay = " ".join(
                str(x) for x in (ev.host, ev.http_path, ev.message, ev.metadata.get("domain", "")) if x
            ).lower()
            for dom, (sev, src) in self._domains.items():
                if dom in hay:
                    hits.append(ThreatMatch(dom, "domain", sev, src, "domain", dom))
        return hits


@dataclass
class AssetEntry:
    host: str = ""
    ip: str = ""
    cidr: str = ""
    tier: str = "tier2"
    owner: str = ""


class AssetCatalog:
    """Lookup asset criticality tiers and escalate tier1 incidents."""

    def __init__(self, entries: list[AssetEntry] | None = None) -> None:
        self._by_host: dict[str, AssetEntry] = {}
        self._by_ip: dict[str, AssetEntry] = {}
        self._cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, AssetEntry]] = []
        for e in entries or []:
            if e.host:
                self._by_host[e.host.lower()] = e
            if e.ip:
                self._by_ip[str(ipaddress.ip_address(e.ip))] = e
            if e.cidr:
                self._cidrs.append((ipaddress.ip_network(e.cidr, strict=False), e))

    def lookup(self, ev: NormalizedEvent) -> AssetEntry | None:
        if ev.host and ev.host.lower() in self._by_host:
            return self._by_host[ev.host.lower()]
        for raw_ip in (ev.dst_ip, ev.src_ip):
            if not raw_ip:
                continue
            try:
                addr = ipaddress.ip_address(raw_ip.strip())
            except ValueError:
                continue
            if str(addr) in self._by_ip:
                return self._by_ip[str(addr)]
            for net, entry in self._cidrs:
                if addr.version == net.version and addr in net:
                    return entry
        return None


@dataclass
class SequenceStep:
    name: str
    match: dict[str, str]

    def matches(self, ev: NormalizedEvent) -> bool:
        for k, expected in self.match.items():
            kl = k.lower()
            exp_low = expected.lower()
            if kl == "category" and ev.category.lower() != exp_low:
                return False
            elif kl == "action" and ev.action.lower() != exp_low:
                return False
            elif kl == "outcome" and ev.outcome.lower() != exp_low:
                return False
            elif kl == "layer" and ev.layer.lower() != exp_low:
                return False
            elif kl in ("source_format", "format") and ev.source_format.lower() != exp_low:
                return False
        return True


@dataclass
class SequenceRule:
    id: str
    title: str
    steps: list[SequenceStep]
    severity: str = "critical"
    window_seconds: int = 900
    group_by: str = "src_ip"


def compute_posture(findings: list[Finding]) -> PostureScore:
    score = 100
    for f in findings:
        score -= _SEV_PENALTY.get(f.severity.lower(), 0)
    if score < 0:
        score = 0
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 55:
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
    """Zero-dependency stateful SIEM correlator matching raksa-siem v0.2.0 rules."""

    def __init__(
        self,
        *,
        auth_burst_threshold: int = 5,
        web_probe_threshold: int = 5,
        alert_storm_threshold: int = 10,
        watched_ips: list[str] | None = None,
        watched_hosts: list[str] | None = None,
        watched_users: list[str] | None = None,
        threat_feed: ThreatFeed | None = None,
        asset_catalog: AssetCatalog | None = None,
        sequence_rules: list[SequenceRule] | None = None,
    ) -> None:
        self.auth_burst_threshold = max(1, auth_burst_threshold)
        self.web_probe_threshold = max(1, web_probe_threshold)
        self.alert_storm_threshold = max(1, alert_storm_threshold)
        self.watched_ips = set(watched_ips or [])
        self.watched_hosts = {h.lower() for h in (watched_hosts or [])}
        self.watched_users = {u.lower() for u in (watched_users or [])}
        self.threat_feed = threat_feed
        self.asset_catalog = asset_catalog
        self.sequence_rules = list(sequence_rules or [])

        self._auth_fails_ip: dict[str, list[datetime]] = defaultdict(list)
        self._web_errs_ip: dict[str, list[datetime]] = defaultdict(list)
        self._layers_ip: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        self._layers_host: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        self._seq_chains: dict[str, list[tuple[datetime, int, list[str]]]] = defaultdict(list)
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
        out: list[Finding] = []
        target = f"host://{ev.host}" if ev.host else (f"ip://{ev.src_ip}" if ev.src_ip else "siem://telemetry")

        if ev.category == "auth":
            if ev.outcome == "failure" and ev.src_ip:
                win10 = timedelta(minutes=10)
                win15 = timedelta(minutes=15)
                times = [t for t in self._auth_fails_ip[ev.src_ip] if ts - t <= win15]
                times.append(ts)
                self._auth_fails_ip[ev.src_ip] = times
                recent = [t for t in times if ts - t <= win10]
                if len(recent) >= self.auth_burst_threshold and self._can_emit("SIEM-001", ev.src_ip, ts, win10):
                    out.append(
                        self._emit(
                            "SIEM-001", "auth", "high", "Authentication brute-force burst detected",
                            f"ip://{ev.src_ip}", "D3-UAL", ts,
                            f"{len(recent)} failed authentication attempts from {ev.src_ip} within 10m.",
                            {"src_ip": ev.src_ip, "failures": len(recent)},
                        )
                    )
            elif ev.outcome == "success" and ev.src_ip:
                win15 = timedelta(minutes=15)
                prior = [t for t in self._auth_fails_ip.get(ev.src_ip, []) if ts - t <= win15]
                if len(prior) >= 3 and self._can_emit("SIEM-002", ev.src_ip, ts, win15):
                    out.append(
                        self._emit(
                            "SIEM-002", "auth", "critical", "Suspicious login success after failures",
                            target, "D3-IAM", ts,
                            f"Source {ev.src_ip} authenticated successfully after {len(prior)} failed attempts.",
                            {"src_ip": ev.src_ip, "user": ev.user, "prior_failures": len(prior)},
                        )
                    )

        if ev.category == "web" and ev.src_ip and ev.http_status in (401, 403, 404):
            win5 = timedelta(minutes=5)
            w_times = [t for t in self._web_errs_ip[ev.src_ip] if ts - t <= win5]
            w_times.append(ts)
            self._web_errs_ip[ev.src_ip] = w_times
            if len(w_times) >= self.web_probe_threshold and self._can_emit("SIEM-101", ev.src_ip, ts, win5):
                out.append(
                    self._emit(
                        "SIEM-101", "web-net", "medium", "HTTP 401/403/404 scan burst detected",
                        f"ip://{ev.src_ip}", "D3-NTA", ts,
                        f"Source {ev.src_ip} triggered {len(w_times)} client error responses within 5m.",
                        {"src_ip": ev.src_ip, "count": len(w_times)},
                    )
                )

        if ev.src_ip and ev.src_ip in self.watched_ips and self._can_emit("SIEM-501", f"ip:{ev.src_ip}", ts, timedelta(minutes=10)):
            out.append(
                self._emit(
                    "SIEM-501", "policy", "high", "Watchlisted entity matched telemetry",
                    f"ip://{ev.src_ip}", "D3-DEN", ts,
                    f"Watchlisted IP {ev.src_ip} observed in {ev.layer}.",
                    {"src_ip": ev.src_ip},
                )
            )

        is_suspicious = (
            _SEV_RANK.get(ev.severity, 1) >= 2
            or ev.outcome in ("failure", "blocked", "alert")
            or ev.action in ("probe", "log_tamper", "finding")
        )
        if is_suspicious and ev.src_ip:
            win30 = timedelta(minutes=30)
            recs = [(t, l) for t, l in self._layers_ip[ev.src_ip] if ts - t <= win30]
            recs.append((ts, ev.layer))
            self._layers_ip[ev.src_ip] = recs
            distinct_layers = sorted({l for _, l in recs if l})
            if len(distinct_layers) >= 2 and self._can_emit("SIEM-201", ev.src_ip, ts, win30):
                out.append(
                    self._emit(
                        "SIEM-201", "correlation", "high", "Single source IP active across multiple Raksa layers",
                        f"ip://{ev.src_ip}", "D3-CA", ts,
                        f"Source IP {ev.src_ip} correlated across {len(distinct_layers)} layers: {', '.join(distinct_layers)}.",
                        {"src_ip": ev.src_ip, "layers": distinct_layers},
                    )
                )

        if is_suspicious and ev.host:
            win30 = timedelta(minutes=30)
            host_key = ev.host.lower()
            h_recs = [(t, l) for t, l in self._layers_host[host_key] if ts - t <= win30]
            h_recs.append((ts, ev.layer))
            self._layers_host[host_key] = h_recs
            h_layers = {l for _, l in h_recs if l}
            if "ioc-defense" in h_layers and ("network-defense" in h_layers or "host-hardening" in h_layers):
                if self._can_emit("SIEM-205", host_key, ts, win30):
                    out.append(
                        self._emit(
                            "SIEM-205", "correlation", "critical", "Malware/IoC hit paired with runtime host or network alert",
                            f"host://{ev.host}", "D3-ER", ts,
                            f"Host {ev.host} correlates ioc-defense findings with runtime defense alerts.",
                            {"host": ev.host, "layers": sorted(h_layers)},
                        )
                    )

        for sq in self.sequence_rules:
            if len(sq.steps) < 2:
                continue
            gval = ev.src_ip if sq.group_by == "src_ip" else (ev.host or ev.user or "global")
            win = timedelta(seconds=sq.window_seconds)
            key = f"{sq.id}|{gval}"
            chains = [(st, idx, ids) for st, idx, ids in self._seq_chains[key] if ts - st <= win]
            next_chains: list[tuple[datetime, int, list[str]]] = []
            completed_ids: list[str] | None = None
            for st, idx, ids in chains:
                n_idx = idx + 1
                if n_idx < len(sq.steps) and sq.steps[n_idx].matches(ev):
                    if n_idx == len(sq.steps) - 1 and completed_ids is None:
                        completed_ids = [*ids, ev.id]
                    else:
                        next_chains.append((st, n_idx, [*ids, ev.id]))
                else:
                    next_chains.append((st, idx, ids))
            if sq.steps[0].matches(ev) and len(next_chains) < 32:
                next_chains.append((ts, 0, [ev.id]))
            self._seq_chains[key] = next_chains
            if completed_ids is not None and self._can_emit(f"seq:{sq.id}", gval, ts, win):
                out.append(
                    self._emit(
                        "SIEM-206", "correlation", sq.severity, f"{sq.title} [{sq.id}]",
                        target, "D3-SCA", ts,
                        f"Ordered sequence {sq.id} matched {len(completed_ids)} stages for {gval}.",
                        {"sequence_id": sq.id, "group_key": gval, "event_ids": completed_ids},
                    )
                )

        if self.threat_feed is not None:
            for tm in self.threat_feed.match_event(ev):
                if self._can_emit("SIEM-502", f"{tm.matched_on}:{tm.matched_val}", ts, timedelta(minutes=15)):
                    out.append(
                        self._emit(
                            "SIEM-502", "policy", tm.severity, "STIX 2.1 or CIDR threat intelligence indicator matched",
                            target, "D3-DA", ts,
                            f"Telemetry {tm.matched_on} ({tm.matched_val}) matched {tm.kind} indicator {tm.value}.",
                            {"indicator": tm.value, "kind": tm.kind, "matched_on": tm.matched_on},
                        )
                    )

        if self.asset_catalog is not None and out:
            asset = self.asset_catalog.lookup(ev)
            if asset is not None:
                for f in out:
                    f.evidence["asset_tier"] = asset.tier
                    if asset.owner:
                        f.evidence["asset_owner"] = asset.owner
                    if asset.tier in ("tier1", "critical"):
                        bump = {"low": "medium", "medium": "high", "high": "critical"}.get(f.severity)
                        if bump:
                            f.evidence["escalated_from"] = f.severity
                            f.severity = bump

        return out

    def analyze_batch(self, events: list[NormalizedEvent]) -> tuple[list[Finding], Timeline]:
        ordered = sorted(events, key=lambda e: (_parse_ts(e.timestamp), e.id))
        findings: list[Finding] = []
        for ev in ordered:
            findings.extend(self.ingest(ev))
        return findings, build_timeline(ordered)
