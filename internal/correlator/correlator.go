package correlator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

const maxTrackedKeys = 10000

// TimelineFilter restricts timeline results to a matching entity or layer.
type TimelineFilter struct {
	SrcIP string `json:"src_ip,omitempty"`
	Host  string `json:"host,omitempty"`
	User  string `json:"user,omitempty"`
	Layer string `json:"layer,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// Timeline summarizes chronological events grouped across entities and layers.
type Timeline struct {
	TotalEvents int            `json:"total_events"`
	ByLayer     map[string]int `json:"by_layer"`
	BySrcIP     map[string]int `json:"by_src_ip"`
	ByHost      map[string]int `json:"by_host"`
	ByUser      map[string]int `json:"by_user"`
	Entries     []schema.Event `json:"entries"`
}

type stampRecord struct {
	ts  time.Time
	val string
	ev  schema.Event
}

// Engine evaluates single-source, windowed burst, and cross-layer attack kill-chain rules safely across goroutines.
type Engine struct {
	mu  sync.Mutex
	pol policy.Policy

	watchedIPs   map[string]bool
	watchedHosts map[string]bool
	watchedUsers map[string]bool

	authFailsByIP     map[string][]time.Time
	authUsersByIP     map[string][]stampRecord
	authIPsByUser     map[string][]stampRecord
	loginIPsByUser    map[string][]stampRecord
	sudoFailByKey     map[string][]time.Time
	webErrByIP        map[string][]time.Time
	webProbesByIP     map[string][]time.Time
	web5xxEvents      []time.Time
	netBlocksByIP     map[string][]time.Time
	highAlertTimes    []time.Time
	layersBySrcIP     map[string][]stampRecord
	layersByHost      map[string][]stampRecord
	hostsByActor      map[string][]stampRecord
	customWindows     map[string][]time.Time
	cooldownByAlertID map[string]time.Time
}

// NewEngine creates a bounded thread-safe correlation engine using pol.
func NewEngine(pol policy.Policy) *Engine {
	_ = pol.ValidateAndCompile()
	wIP := make(map[string]bool, len(pol.WatchedIPs))
	for _, s := range pol.WatchedIPs {
		if strings.TrimSpace(s) != "" {
			wIP[strings.TrimSpace(s)] = true
		}
	}
	wHost := make(map[string]bool, len(pol.WatchedHosts))
	for _, s := range pol.WatchedHosts {
		if strings.TrimSpace(s) != "" {
			wHost[strings.ToLower(strings.TrimSpace(s))] = true
		}
	}
	wUser := make(map[string]bool, len(pol.WatchedUsers))
	for _, s := range pol.WatchedUsers {
		if strings.TrimSpace(s) != "" {
			wUser[strings.ToLower(strings.TrimSpace(s))] = true
		}
	}
	return &Engine{
		pol:               pol,
		watchedIPs:        wIP,
		watchedHosts:      wHost,
		watchedUsers:      wUser,
		authFailsByIP:     make(map[string][]time.Time),
		authUsersByIP:     make(map[string][]stampRecord),
		authIPsByUser:     make(map[string][]stampRecord),
		loginIPsByUser:    make(map[string][]stampRecord),
		sudoFailByKey:     make(map[string][]time.Time),
		webErrByIP:        make(map[string][]time.Time),
		webProbesByIP:     make(map[string][]time.Time),
		netBlocksByIP:     make(map[string][]time.Time),
		layersBySrcIP:     make(map[string][]stampRecord),
		layersByHost:      make(map[string][]stampRecord),
		hostsByActor:      make(map[string][]stampRecord),
		customWindows:     make(map[string][]time.Time),
		cooldownByAlertID: make(map[string]time.Time),
	}
}

// AnalyzeBatch sorts events chronologically, runs stateful correlation, and returns sorted findings + Timeline.
func AnalyzeBatch(events []schema.Event, pol policy.Policy) ([]schema.Finding, Timeline) {
	sorted := make([]schema.Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Timestamp.Equal(sorted[j].Timestamp) {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	eng := NewEngine(pol)
	var all []schema.Finding
	seen := make(map[string]bool)
	for _, ev := range sorted {
		for _, f := range eng.Ingest(ev) {
			if !seen[f.ID] {
				seen[f.ID] = true
				all = append(all, f)
			}
		}
	}
	SortFindings(all)
	return all, BuildTimeline(sorted, TimelineFilter{})
}

// SortFindings sorts findings deterministically by severity rank descending, rule_id, target, and id.
func SortFindings(findings []schema.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		return findings[i].ID < findings[j].ID
	})
}

// BuildTimeline organizes events chronologically with entity and layer frequency summaries.
func BuildTimeline(events []schema.Event, filter TimelineFilter) Timeline {
	tl := Timeline{
		ByLayer: make(map[string]int),
		BySrcIP: make(map[string]int),
		ByHost:  make(map[string]int),
		ByUser:  make(map[string]int),
	}
	var filtered []schema.Event
	for _, ev := range events {
		if filter.SrcIP != "" && ev.SrcIP != filter.SrcIP {
			continue
		}
		if filter.Host != "" && !strings.EqualFold(ev.Host, filter.Host) {
			continue
		}
		if filter.User != "" && !strings.EqualFold(ev.User, filter.User) {
			continue
		}
		if filter.Layer != "" && !strings.EqualFold(ev.Layer, filter.Layer) {
			continue
		}
		filtered = append(filtered, ev)
		if ev.Layer != "" {
			tl.ByLayer[ev.Layer]++
		}
		if ev.SrcIP != "" {
			tl.BySrcIP[ev.SrcIP]++
		}
		if ev.Host != "" {
			tl.ByHost[ev.Host]++
		}
		if ev.User != "" {
			tl.ByUser[ev.User]++
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Timestamp.Equal(filtered[j].Timestamp) {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].Timestamp.Before(filtered[j].Timestamp)
	})
	if filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[len(filtered)-filter.Limit:]
	}
	tl.TotalEvents = len(filtered)
	tl.Entries = filtered
	return tl
}

// Ingest processes a single normalized Event thread-safely and emits correlated SIEM findings.
func (e *Engine) Ingest(ev schema.Event) []schema.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()

	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	var out []schema.Finding

	// 1. Auth rules (SIEM-001 .. SIEM-005)
	if ev.Category == "auth" {
		if ev.Outcome == "failure" {
			if ev.SrcIP != "" {
				e.authFailsByIP[ev.SrcIP] = appendPruneTime(e.authFailsByIP[ev.SrcIP], ts, 15*time.Minute)
				if countWithin(e.authFailsByIP[ev.SrcIP], ts, 10*time.Minute) >= e.pol.AuthBurstThreshold {
					if e.canEmit("SIEM-001", ev.SrcIP, ts, 10*time.Minute) {
						out = append(out, makeFinding("SIEM-001", "ip://"+ev.SrcIP, ts,
							fmt.Sprintf("%d failed auth attempts from %s within 10m.", len(e.authFailsByIP[ev.SrcIP]), ev.SrcIP),
							map[string]any{"src_ip": ev.SrcIP, "failures": len(e.authFailsByIP[ev.SrcIP]), "host": ev.Host},
						))
					}
				}
				if ev.User != "" {
					e.authUsersByIP[ev.SrcIP] = appendPruneRecord(e.authUsersByIP[ev.SrcIP], stampRecord{ts: ts, val: ev.User, ev: ev}, 10*time.Minute)
					if distinctVals(e.authUsersByIP[ev.SrcIP]) >= 4 && e.canEmit("SIEM-003", "ip:"+ev.SrcIP, ts, 10*time.Minute) {
						out = append(out, makeFinding("SIEM-003", "ip://"+ev.SrcIP, ts,
							fmt.Sprintf("Source %s sprayed failed logins across %d distinct accounts.", ev.SrcIP, distinctVals(e.authUsersByIP[ev.SrcIP])),
							map[string]any{"src_ip": ev.SrcIP, "distinct_users": distinctVals(e.authUsersByIP[ev.SrcIP])},
						))
					}
				}
			}
			if ev.User != "" && ev.SrcIP != "" {
				e.authIPsByUser[ev.User] = appendPruneRecord(e.authIPsByUser[ev.User], stampRecord{ts: ts, val: ev.SrcIP, ev: ev}, 10*time.Minute)
				if distinctVals(e.authIPsByUser[ev.User]) >= 4 && e.canEmit("SIEM-003", "user:"+ev.User, ts, 10*time.Minute) {
					out = append(out, makeFinding("SIEM-003", "user://"+ev.User, ts,
						fmt.Sprintf("Account %q targeted from %d distinct source IPs within 10m.", ev.User, distinctVals(e.authIPsByUser[ev.User])),
						map[string]any{"user": ev.User, "distinct_ips": distinctVals(e.authIPsByUser[ev.User])},
					))
				}
			}
		}

		if ev.Outcome == "success" {
			if ev.SrcIP != "" && countWithin(e.authFailsByIP[ev.SrcIP], ts, 15*time.Minute) >= 3 {
				if e.canEmit("SIEM-002", ev.SrcIP, ts, 15*time.Minute) {
					out = append(out, makeFinding("SIEM-002", targetForEvent(ev), ts,
						fmt.Sprintf("Source %s succeeded login (%q) after %d recent authentication failures.", ev.SrcIP, ev.User, countWithin(e.authFailsByIP[ev.SrcIP], ts, 15*time.Minute)),
						map[string]any{"src_ip": ev.SrcIP, "user": ev.User, "host": ev.Host, "prior_failures": countWithin(e.authFailsByIP[ev.SrcIP], ts, 15*time.Minute)},
					))
				}
			}
			if ev.User != "" && ev.SrcIP != "" {
				e.loginIPsByUser[ev.User] = appendPruneRecord(e.loginIPsByUser[ev.User], stampRecord{ts: ts, val: ev.SrcIP, ev: ev}, 15*time.Minute)
				if distinctVals(e.loginIPsByUser[ev.User]) >= 3 && e.canEmit("SIEM-005", ev.User, ts, 15*time.Minute) {
					out = append(out, makeFinding("SIEM-005", "user://"+ev.User, ts,
						fmt.Sprintf("User %q logged in from %d distinct source IPs inside 15m.", ev.User, distinctVals(e.loginIPsByUser[ev.User])),
						map[string]any{"user": ev.User, "distinct_ips": distinctVals(e.loginIPsByUser[ev.User])},
					))
				}
			}
		}
	}

	// SIEM-004: Privilege escalation / persistence command
	if ev.Category == "privilege" {
		if ev.Action == "account_change" || (ev.Outcome == "success" && ev.Severity.MeetsThreshold(schema.SeverityHigh)) {
			if e.canEmit("SIEM-004", ev.Host+":"+ev.User+":"+ev.Action, ts, 10*time.Minute) {
				out = append(out, makeFinding("SIEM-004", targetForEvent(ev), ts,
					fmt.Sprintf("High-risk privilege/account event on %s for user %q: %s", defaultHost(ev.Host), ev.User, ev.Message),
					map[string]any{"host": ev.Host, "user": ev.User, "action": ev.Action},
				))
			}
		} else if ev.Outcome == "failure" {
			k := ev.Host + ":" + ev.User
			e.sudoFailByKey[k] = appendPruneTime(e.sudoFailByKey[k], ts, 10*time.Minute)
			if len(e.sudoFailByKey[k]) >= 3 && e.canEmit("SIEM-004", "fail:"+k, ts, 10*time.Minute) {
				out = append(out, makeFinding("SIEM-004", targetForEvent(ev), ts,
					fmt.Sprintf("Repeated sudo/su privilege escalation failures (%d) for user %q.", len(e.sudoFailByKey[k]), ev.User),
					map[string]any{"host": ev.Host, "user": ev.User, "failures": len(e.sudoFailByKey[k])},
				))
			}
		}
	}

	// 2. Web & Network rules (SIEM-101 .. SIEM-104)
	if ev.Category == "web" {
		if ev.SrcIP != "" && (ev.HTTPStatus == 401 || ev.HTTPStatus == 403 || ev.HTTPStatus == 404) {
			e.webErrByIP[ev.SrcIP] = appendPruneTime(e.webErrByIP[ev.SrcIP], ts, 5*time.Minute)
			if len(e.webErrByIP[ev.SrcIP]) >= e.pol.WebProbeThreshold && e.canEmit("SIEM-101", ev.SrcIP, ts, 5*time.Minute) {
				out = append(out, makeFinding("SIEM-101", "ip://"+ev.SrcIP, ts,
					fmt.Sprintf("Source %s triggered %d HTTP 401/403/404 responses within 5m.", ev.SrcIP, len(e.webErrByIP[ev.SrcIP])),
					map[string]any{"src_ip": ev.SrcIP, "error_count": len(e.webErrByIP[ev.SrcIP]), "last_path": ev.HTTPPath},
				))
			}
		}
		if ev.SrcIP != "" && (ev.Action == "probe" || strings.HasPrefix(ev.RuleID, "WEB-1") || ev.RuleID == "WEB-311") {
			e.webProbesByIP[ev.SrcIP] = appendPruneTime(e.webProbesByIP[ev.SrcIP], ts, 5*time.Minute)
			if len(e.webProbesByIP[ev.SrcIP]) >= 3 && e.canEmit("SIEM-102", ev.SrcIP, ts, 5*time.Minute) {
				out = append(out, makeFinding("SIEM-102", "ip://"+ev.SrcIP, ts,
					fmt.Sprintf("Source %s launched %d web exploit/WAF probes within 5m.", ev.SrcIP, len(e.webProbesByIP[ev.SrcIP])),
					map[string]any{"src_ip": ev.SrcIP, "probe_count": len(e.webProbesByIP[ev.SrcIP]), "last_path": ev.HTTPPath},
				))
			}
		}
		if ev.HTTPStatus >= 500 {
			e.web5xxEvents = appendPruneTime(e.web5xxEvents, ts, 5*time.Minute)
			if len(e.web5xxEvents) >= 5 && e.canEmit("SIEM-103", defaultHost(ev.Host), ts, 5*time.Minute) {
				out = append(out, makeFinding("SIEM-103", targetForEvent(ev), ts,
					fmt.Sprintf("Observed %d HTTP 5xx server error responses within 5m.", len(e.web5xxEvents)),
					map[string]any{"host": ev.Host, "errors_5xx": len(e.web5xxEvents), "last_status": ev.HTTPStatus},
				))
			}
		}
	}

	if (ev.Layer == "network-defense" || (ev.Category == "network" && ev.Severity.MeetsThreshold(schema.SeverityMedium))) && ev.SrcIP != "" {
		e.netBlocksByIP[ev.SrcIP] = appendPruneTime(e.netBlocksByIP[ev.SrcIP], ts, 10*time.Minute)
		if len(e.netBlocksByIP[ev.SrcIP]) >= 3 && e.canEmit("SIEM-104", ev.SrcIP, ts, 10*time.Minute) {
			out = append(out, makeFinding("SIEM-104", "ip://"+ev.SrcIP, ts,
				fmt.Sprintf("Network defense reported %d alerts/blocks for %s inside 10m.", len(e.netBlocksByIP[ev.SrcIP]), ev.SrcIP),
				map[string]any{"src_ip": ev.SrcIP, "count": len(e.netBlocksByIP[ev.SrcIP])},
			))
		}
	}

	// 3. Upstream Critical, Alert Storm, Tampering (SIEM-301 .. SIEM-303)
	if isUpstreamRaksaRule(ev.RuleID) && ev.Severity == schema.SeverityCritical {
		if e.canEmit("SIEM-301", ev.ID, ts, 10*time.Minute) {
			out = append(out, makeFinding("SIEM-301", targetForEvent(ev), ts,
				fmt.Sprintf("Upstream layer %s emitted critical finding %s: %s", ev.Layer, ev.RuleID, ev.Message),
				map[string]any{"upstream_rule": ev.RuleID, "upstream_layer": ev.Layer, "src_ip": ev.SrcIP, "host": ev.Host},
			))
		}
	}
	if ev.Severity.MeetsThreshold(schema.SeverityHigh) {
		e.highAlertTimes = appendPruneTime(e.highAlertTimes, ts, 5*time.Minute)
		if len(e.highAlertTimes) >= e.pol.AlertStormThreshold && e.canEmit("SIEM-302", "global", ts, 5*time.Minute) {
			out = append(out, makeFinding("SIEM-302", "siem://global-stream", ts,
				fmt.Sprintf("Observed %d high/critical telemetry alerts within 5m.", len(e.highAlertTimes)),
				map[string]any{"alert_count": len(e.highAlertTimes), "window": "5m"},
			))
		}
	}
	if ev.Action == "log_tamper" {
		if e.canEmit("SIEM-303", defaultHost(ev.Host)+":"+ev.Message, ts, 10*time.Minute) {
			out = append(out, makeFinding("SIEM-303", targetForEvent(ev), ts,
				fmt.Sprintf("Telemetry clearing or log tampering indicator on %s: %s", defaultHost(ev.Host), ev.Message),
				map[string]any{"host": ev.Host, "process": ev.Process, "raw": ev.Message},
			))
		}
	}

	// 4. Watchlist hits (SIEM-501)
	if ev.SrcIP != "" && e.watchedIPs[ev.SrcIP] && e.canEmit("SIEM-501", "ip:"+ev.SrcIP, ts, 10*time.Minute) {
		out = append(out, makeFinding("SIEM-501", "ip://"+ev.SrcIP, ts,
			fmt.Sprintf("Watchlisted IP %s appeared in %s telemetry.", ev.SrcIP, ev.Layer),
			map[string]any{"match_type": "watched_ip", "src_ip": ev.SrcIP, "layer": ev.Layer},
		))
	}
	if ev.Host != "" && e.watchedHosts[strings.ToLower(ev.Host)] && e.canEmit("SIEM-501", "host:"+strings.ToLower(ev.Host), ts, 10*time.Minute) {
		out = append(out, makeFinding("SIEM-501", "host://"+ev.Host, ts,
			fmt.Sprintf("Watchlisted host %q reported telemetry.", ev.Host),
			map[string]any{"match_type": "watched_host", "host": ev.Host, "layer": ev.Layer},
		))
	}
	if ev.User != "" && e.watchedUsers[strings.ToLower(ev.User)] && e.canEmit("SIEM-501", "user:"+strings.ToLower(ev.User), ts, 10*time.Minute) {
		out = append(out, makeFinding("SIEM-501", "user://"+ev.User, ts,
			fmt.Sprintf("Watchlisted account %q observed in %s event.", ev.User, ev.Layer),
			map[string]any{"match_type": "watched_user", "user": ev.User, "layer": ev.Layer},
		))
	}

	// 5. Cross-Layer Correlation (SIEM-201 .. SIEM-205)
	if isSuspiciousForCorrelation(ev) {
		if ev.SrcIP != "" {
			e.layersBySrcIP[ev.SrcIP] = appendPruneRecord(e.layersBySrcIP[ev.SrcIP], stampRecord{ts: ts, val: ev.Layer, ev: ev}, 30*time.Minute)
			layers := collectDistinctVals(e.layersBySrcIP[ev.SrcIP])
			if len(layers) >= 2 && e.canEmit("SIEM-201", ev.SrcIP, ts, 30*time.Minute) {
				out = append(out, makeFinding("SIEM-201", "ip://"+ev.SrcIP, ts,
					fmt.Sprintf("Source IP %s triggered security events across %d layers: %s.", ev.SrcIP, len(layers), strings.Join(layers, ", ")),
					map[string]any{"src_ip": ev.SrcIP, "layers": layers, "event_count": len(e.layersBySrcIP[ev.SrcIP])},
				))
			}
			if ev.Host != "" {
				actorKey := "ip:" + ev.SrcIP
				e.hostsByActor[actorKey] = appendPruneRecord(e.hostsByActor[actorKey], stampRecord{ts: ts, val: ev.Host, ev: ev}, 30*time.Minute)
				hosts := collectDistinctVals(e.hostsByActor[actorKey])
				if len(hosts) >= 3 && e.canEmit("SIEM-203", actorKey, ts, 30*time.Minute) {
					out = append(out, makeFinding("SIEM-203", "ip://"+ev.SrcIP, ts,
						fmt.Sprintf("Source IP %s touched %d distinct target hosts within 30m: %s.", ev.SrcIP, len(hosts), strings.Join(hosts, ", ")),
						map[string]any{"src_ip": ev.SrcIP, "hosts": hosts},
					))
				}
			}
		}

		if ev.User != "" && ev.Host != "" {
			actorKey := "user:" + strings.ToLower(ev.User)
			e.hostsByActor[actorKey] = appendPruneRecord(e.hostsByActor[actorKey], stampRecord{ts: ts, val: ev.Host, ev: ev}, 30*time.Minute)
			hosts := collectDistinctVals(e.hostsByActor[actorKey])
			if len(hosts) >= 3 && e.canEmit("SIEM-203", actorKey, ts, 30*time.Minute) {
				out = append(out, makeFinding("SIEM-203", "user://"+ev.User, ts,
					fmt.Sprintf("Account %q accessed or failed across %d distinct hosts within 30m: %s.", ev.User, len(hosts), strings.Join(hosts, ", ")),
					map[string]any{"user": ev.User, "hosts": hosts},
				))
			}
		}

		if ev.Host != "" {
			hostKey := strings.ToLower(ev.Host)
			e.layersByHost[hostKey] = appendPruneRecord(e.layersByHost[hostKey], stampRecord{ts: ts, val: ev.Layer, ev: ev}, 60*time.Minute)
			recs := e.layersByHost[hostKey]
			recentLayers := distinctValsWithin(recs, ts, 30*time.Minute)
			if len(recentLayers) >= 2 && e.canEmit("SIEM-202", hostKey, ts, 30*time.Minute) {
				out = append(out, makeFinding("SIEM-202", "host://"+ev.Host, ts,
					fmt.Sprintf("Host %q reported alerts across %d layers: %s.", ev.Host, len(recentLayers), strings.Join(recentLayers, ", ")),
					map[string]any{"host": ev.Host, "layers": recentLayers},
				))
			}
			// SIEM-204: devsecops + runtime layer on same host
			hasDevSecOps := containsVal(collectDistinctVals(recs), "devsecops")
			hasRuntime := hasAnyVal(recentLayers, "network-defense", "host-hardening", "web-defense", "ioc-defense")
			if hasDevSecOps && hasRuntime && e.canEmit("SIEM-204", hostKey, ts, 60*time.Minute) {
				out = append(out, makeFinding("SIEM-204", "host://"+ev.Host, ts,
					fmt.Sprintf("Host %q combines DevSecOps pipeline exposure with runtime alerts.", ev.Host),
					map[string]any{"host": ev.Host, "layers": collectDistinctVals(recs)},
				))
			}
			// SIEM-205: malware/IoC + network/host runtime compromise
			hasIOC := containsVal(recentLayers, "ioc-defense")
			hasHostOrNet := hasAnyVal(recentLayers, "network-defense", "host-hardening")
			if hasIOC && hasHostOrNet && e.canEmit("SIEM-205", hostKey, ts, 30*time.Minute) {
				out = append(out, makeFinding("SIEM-205", "host://"+ev.Host, ts,
					fmt.Sprintf("Host %q exhibits both malware/IoC findings and network/host runtime compromise.", ev.Host),
					map[string]any{"host": ev.Host, "layers": recentLayers},
				))
			}
		}
	}

	// 6. Custom Detection-as-Code YAML Rules (SIEM-401 / SIEM-402)
	for _, cr := range e.pol.CustomRules {
		if !cr.MatchesEvent(ev) {
			continue
		}
		gVal := groupValue(ev, cr.GroupBy)
		if cr.Threshold <= 1 {
			if e.canEmit("custom:"+cr.ID, gVal+":"+ev.ID, ts, time.Minute) {
				out = append(out, makeCustomFinding("SIEM-401", cr, targetForEvent(ev), ts, gVal, 1))
			}
			continue
		}
		key := cr.ID + "|" + gVal
		win := cr.WindowDuration()
		e.customWindows[key] = appendPruneTime(e.customWindows[key], ts, win)
		cnt := len(e.customWindows[key])
		if cnt >= cr.Threshold && e.canEmit("custom:"+cr.ID, gVal, ts, win) {
			out = append(out, makeCustomFinding("SIEM-402", cr, targetForEvent(ev), ts, gVal, cnt))
		}
	}

	e.pruneMapsIfNeeded(ts)
	return out
}

func (e *Engine) canEmit(ruleID, groupKey string, ts time.Time, cooldown time.Duration) bool {
	key := ruleID + "|" + groupKey
	if last, ok := e.cooldownByAlertID[key]; ok {
		if ts.Sub(last) < cooldown {
			return false
		}
	}
	e.cooldownByAlertID[key] = ts
	return true
}

func (e *Engine) pruneMapsIfNeeded(now time.Time) {
	if len(e.authFailsByIP) > maxTrackedKeys {
		e.authFailsByIP = make(map[string][]time.Time)
	}
	if len(e.layersBySrcIP) > maxTrackedKeys {
		e.layersBySrcIP = make(map[string][]stampRecord)
	}
	if len(e.layersByHost) > maxTrackedKeys {
		e.layersByHost = make(map[string][]stampRecord)
	}
	if len(e.hostsByActor) > maxTrackedKeys {
		e.hostsByActor = make(map[string][]stampRecord)
	}
	if len(e.cooldownByAlertID) > maxTrackedKeys {
		cutoff := now.Add(-2 * time.Hour)
		for k, v := range e.cooldownByAlertID {
			if v.Before(cutoff) {
				delete(e.cooldownByAlertID, k)
			}
		}
	}
}

func isUpstreamRaksaRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "NET-") ||
		strings.HasPrefix(ruleID, "HOST-") ||
		strings.HasPrefix(ruleID, "WEB-") ||
		strings.HasPrefix(ruleID, "PIPE-") ||
		strings.HasPrefix(ruleID, "IOC-")
}

func isSuspiciousForCorrelation(ev schema.Event) bool {
	if ev.Severity.MeetsThreshold(schema.SeverityMedium) || isUpstreamRaksaRule(ev.RuleID) {
		return true
	}
	switch ev.Outcome {
	case "failure", "blocked", "attempt", "alert":
		return true
	}
	return ev.Action == "probe" || ev.Action == "log_tamper" || ev.Category == "privilege"
}

func makeFinding(ruleID, target string, ts time.Time, desc string, evidence map[string]any) schema.Finding {
	meta, _ := schema.LookupRule(ruleID)
	h := sha256.Sum256([]byte(ruleID + "|" + target))
	id := strings.ToLower(ruleID) + "-" + hex.EncodeToString(h[:])[:10]
	return schema.Finding{
		ID:          id,
		RuleID:      ruleID,
		Module:      meta.Module,
		Layer:       schema.LayerName,
		Severity:    meta.Severity,
		Title:       meta.Title,
		Description: desc,
		Target:      target,
		Evidence:    evidence,
		Remediation: remediationForRule(ruleID),
		MitreD3FEND: meta.MitreD3FEND,
		Timestamp:   ts.UTC(),
	}
}

func makeCustomFinding(ruleID string, cr policy.CustomRule, target string, ts time.Time, groupKey string, count int) schema.Finding {
	h := sha256.Sum256([]byte(ruleID + "|" + cr.ID + "|" + groupKey + "|" + target))
	desc := cr.Description
	if desc == "" {
		desc = fmt.Sprintf("Custom rule %s (%s) matched %d event(s) for group %q.", cr.ID, cr.Title, count, groupKey)
	}
	rem := cr.Remediation
	if rem == "" {
		rem = "Review matching telemetry events and enforce incident response playbook."
	}
	return schema.Finding{
		ID:          strings.ToLower(ruleID) + "-" + hex.EncodeToString(h[:])[:10],
		RuleID:      ruleID,
		Module:      cr.Module,
		Layer:       schema.LayerName,
		Severity:    cr.Severity,
		Title:       fmt.Sprintf("%s [%s]", cr.Title, cr.ID),
		Description: desc,
		Target:      target,
		Evidence: map[string]any{
			"custom_rule_id": cr.ID,
			"group_key":      groupKey,
			"matched_count":  count,
		},
		Remediation: rem,
		MitreD3FEND: cr.MitreD3FEND,
		Timestamp:   ts.UTC(),
	}
}

func remediationForRule(ruleID string) string {
	switch ruleID {
	case "SIEM-001", "SIEM-002", "SIEM-003":
		return "Block offending source IPs at perimeter firewall, enforce MFA, and rotate targeted credentials."
	case "SIEM-004":
		return "Audit sudoers/account changes immediately and verify whether privilege elevation was authorized."
	case "SIEM-005":
		return "Revoke active user tokens/sessions and require MFA re-verification."
	case "SIEM-101", "SIEM-102", "SIEM-103":
		return "Apply WAF rate-limiting or IP blocks via raksa-webshield and inspect upstream application logs."
	case "SIEM-104":
		return "Verify host firewall deny rules and correlate offending IP with raksa-netguard flow records."
	case "SIEM-201", "SIEM-202", "SIEM-203":
		return "Isolate affected hosts/accounts immediately and execute cross-layer IR triage across NetGuard/HostGuard/IOCScan."
	case "SIEM-204":
		return "Patch or revoke vulnerable/leaked dependencies identified in CI/CD before redeploying runtime workload."
	case "SIEM-205":
		return "Quarantine flagged artifacts via raksa-iocscan and kill suspicious persistence processes on the host."
	case "SIEM-301", "SIEM-302":
		return "Escalate critical findings to SOC triage and enable automated alert routing."
	case "SIEM-303":
		return "Preserve immutable off-host logs and inspect host integrity with raksa-hostguard FIM."
	case "SIEM-501":
		return "Inspect activity associated with the watchlisted IP/host/user and tighten monitoring."
	default:
		return "Investigate correlated SIEM incident and remediate affected asset."
	}
}

func targetForEvent(ev schema.Event) string {
	if ev.Host != "" {
		return "host://" + ev.Host
	}
	if ev.SrcIP != "" {
		return "ip://" + ev.SrcIP
	}
	if ev.User != "" {
		return "user://" + ev.User
	}
	if ev.Path != "" {
		return "file://" + ev.Path
	}
	return "siem://telemetry"
}

func defaultHost(h string) string {
	if h == "" {
		return "unknown-host"
	}
	return h
}

func groupValue(ev schema.Event, groupBy string) string {
	switch strings.ToLower(strings.TrimSpace(groupBy)) {
	case "host":
		return defaultHost(ev.Host)
	case "user":
		return defaultHost(ev.User)
	case "layer":
		return ev.Layer
	case "global":
		return "global"
	default:
		if ev.SrcIP != "" {
			return ev.SrcIP
		}
		return targetForEvent(ev)
	}
}

func appendPruneTime(list []time.Time, now time.Time, maxAge time.Duration) []time.Time {
	cutoff := now.Add(-maxAge)
	kept := list[:0]
	for _, t := range list {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	return append(kept, now)
}

func countWithin(list []time.Time, now time.Time, win time.Duration) int {
	cutoff := now.Add(-win)
	cnt := 0
	for _, t := range list {
		if !t.Before(cutoff) {
			cnt++
		}
	}
	return cnt
}

func appendPruneRecord(list []stampRecord, rec stampRecord, maxAge time.Duration) []stampRecord {
	cutoff := rec.ts.Add(-maxAge)
	kept := list[:0]
	for _, r := range list {
		if !r.ts.Before(cutoff) {
			kept = append(kept, r)
		}
	}
	return append(kept, rec)
}

func distinctVals(list []stampRecord) int {
	return len(collectDistinctVals(list))
}

func distinctValsWithin(list []stampRecord, now time.Time, win time.Duration) []string {
	cutoff := now.Add(-win)
	set := make(map[string]bool)
	var vals []string
	for _, r := range list {
		if !r.ts.Before(cutoff) && r.val != "" && !set[r.val] {
			set[r.val] = true
			vals = append(vals, r.val)
		}
	}
	sort.Strings(vals)
	return vals
}

func collectDistinctVals(list []stampRecord) []string {
	set := make(map[string]bool)
	var vals []string
	for _, r := range list {
		if r.val != "" && !set[r.val] {
			set[r.val] = true
			vals = append(vals, r.val)
		}
	}
	sort.Strings(vals)
	return vals
}

func containsVal(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func hasAnyVal(list []string, targets ...string) bool {
	for _, item := range list {
		for _, t := range targets {
			if item == t {
				return true
			}
		}
	}
	return false
}
