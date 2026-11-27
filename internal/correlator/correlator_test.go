package correlator

import (
	"fmt"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestCorrelatorAllTwentyRulesAndTimeline(t *testing.T) {
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

	pol := policy.DefaultPolicy()
	pol.WatchedIPs = []string{"198.51.100.10"}
	pol.CustomRules = []policy.CustomRule{
		{
			ID:       "ORG-MATCH-1",
			Title:    "Match suspicious debug dump",
			Severity: schema.SeverityHigh,
			Match:    map[string]string{"contains": "MEMDUMP_TOKEN"},
		},
		{
			ID:        "ORG-BURST-2",
			Title:     "Multiple API token errors",
			Severity:  schema.SeverityHigh,
			Match:     map[string]string{"category": "telemetry", "contains": "TOKEN_ERR"},
			Threshold: 3,
			Window:    "5m",
			GroupBy:   "host",
		},
	}

	var events []schema.Event

	// 1. SIEM-001 (5 auth failures), SIEM-002 (subsequent success), SIEM-003 (spray across 4 accounts), SIEM-501 (watched IP)
	for idx, u := range []string{"admin", "root", "deploy", "ops", "backup"} {
		events = append(events, schema.Event{
			ID: fmt.Sprintf("af-%d", idx), Timestamp: t0.Add(time.Duration(idx) * time.Second),
			Layer: "host-hardening", Severity: schema.SeverityLow, Category: "auth", Action: "login", Outcome: "failure",
			SrcIP: "198.51.100.10", Host: "bastion-01", User: u, Message: "Failed password",
		})
	}
	events = append(events, schema.Event{
		ID: "as-1", Timestamp: t0.Add(10 * time.Second),
		Layer: "host-hardening", Severity: schema.SeverityInfo, Category: "auth", Action: "login", Outcome: "success",
		SrcIP: "198.51.100.10", Host: "bastion-01", User: "ops", Message: "Accepted publickey",
	})

	// 2. SIEM-004 (privilege sudo/account change) & SIEM-005 (multi-IP login for "alice")
	events = append(events, schema.Event{
		ID: "priv-1", Timestamp: t0.Add(15 * time.Second),
		Layer: "host-hardening", Severity: schema.SeverityHigh, Category: "privilege", Action: "account_change", Outcome: "success",
		Host: "app-01", User: "backdoor", Message: "new user added",
	})
	for idx, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		events = append(events, schema.Event{
			ID: fmt.Sprintf("mip-%d", idx), Timestamp: t0.Add(time.Duration(20+idx) * time.Second),
			Layer: "host-hardening", Severity: schema.SeverityInfo, Category: "auth", Action: "login", Outcome: "success",
			SrcIP: ip, Host: "bastion-01", User: "alice", Message: "Accepted password",
		})
	}

	// 3. SIEM-101 (404 burst), SIEM-102 (web probes), SIEM-103 (5xx burst), SIEM-104 (network alerts)
	for i := 0; i < 5; i++ {
		events = append(events, schema.Event{
			ID: fmt.Sprintf("web-%d", i), Timestamp: t0.Add(time.Duration(30+i) * time.Second),
			Layer: "web-defense", Severity: schema.SeverityMedium, Category: "web", Action: "probe", Outcome: "blocked",
			SrcIP: "198.51.100.10", Host: "app-01", HTTPStatus: 403, HTTPPath: "/../.env", Message: "probe blocked",
		})
		events = append(events, schema.Event{
			ID: fmt.Sprintf("web5-%d", i), Timestamp: t0.Add(time.Duration(40+i) * time.Second),
			Layer: "web-defense", Severity: schema.SeverityMedium, Category: "web", Action: "server_error", Outcome: "error",
			SrcIP: "203.0.113.99", Host: "app-01", HTTPStatus: 502, Message: "bad gateway",
		})
	}
	for i := 0; i < 3; i++ {
		events = append(events, schema.Event{
			ID: fmt.Sprintf("net-%d", i), Timestamp: t0.Add(time.Duration(50+i) * time.Second),
			Layer: "network-defense", Severity: schema.SeverityHigh, Category: "network", Action: "finding", Outcome: "alert",
			RuleID: "NET-101", SrcIP: "198.51.100.10", Host: fmt.Sprintf("db-0%d", i+1), Message: "scan alert",
		})
	}
	for i := 0; i < 5; i++ {
		events = append(events, schema.Event{
			ID: fmt.Sprintf("storm-%d", i), Timestamp: t0.Add(time.Duration(55+i) * time.Second),
			Layer: "network-defense", Severity: schema.SeverityHigh, Category: "network", Action: "finding", Outcome: "alert",
			RuleID: "NET-105", SrcIP: "203.0.113.77", Host: "edge-01", Message: "blocked SYN burst",
		})
	}

	// 4. SIEM-201 (cross-layer IP), SIEM-202 (cross-layer host), SIEM-203 (lateral >=3 hosts by 198.51.100.10),
	//    SIEM-204 (devsecops + runtime on app-01), SIEM-205 (ioc-defense + host/network on app-01), SIEM-301 (critical), SIEM-302 (storm >=10 high/crit), SIEM-303 (tamper)
	events = append(events,
		schema.Event{
			ID: "pipe-1", Timestamp: t0.Add(60 * time.Second),
			Layer: "devsecops", Severity: schema.SeverityHigh, Category: "devsecops", Action: "finding", Outcome: "alert",
			RuleID: "PIPE-001", Host: "app-01", Message: "hardcoded secret in app-01 repo",
		},
		schema.Event{
			ID: "ioc-crit-1", Timestamp: t0.Add(65 * time.Second),
			Layer: "ioc-defense", Severity: schema.SeverityCritical, Category: "malware", Action: "finding", Outcome: "alert",
			RuleID: "IOC-001", SrcIP: "198.51.100.10", Host: "app-01", Message: "malware hash detected",
		},
		schema.Event{
			ID: "tamper-1", Timestamp: t0.Add(70 * time.Second),
			Layer: "host-hardening", Severity: schema.SeverityMedium, Category: "ops", Action: "log_tamper", Outcome: "observed",
			Host: "app-01", Message: "history -c",
		},
		schema.Event{
			ID: "cust-1", Timestamp: t0.Add(72 * time.Second),
			Layer: "telemetry", Severity: schema.SeverityMedium, Category: "telemetry", Action: "event", Outcome: "observed",
			Host: "app-01", Message: "MEMDUMP_TOKEN invoked",
		},
	)
	for i := 0; i < 3; i++ {
		events = append(events, schema.Event{
			ID: fmt.Sprintf("cust-b-%d", i), Timestamp: t0.Add(time.Duration(75+i) * time.Second),
			Layer: "telemetry", Severity: schema.SeverityLow, Category: "telemetry", Action: "event", Outcome: "observed",
			Host: "api-01", Message: "TOKEN_ERR retry",
		})
	}

	findings, tl := AnalyzeBatch(events, pol)
	if tl.TotalEvents != len(events) {
		t.Fatalf("expected timeline total=%d, got %d", len(events), tl.TotalEvents)
	}

	hitSet := make(map[string]bool)
	for _, f := range findings {
		hitSet[f.RuleID] = true
	}

	expected := []string{
		"SIEM-001", "SIEM-002", "SIEM-003", "SIEM-004", "SIEM-005",
		"SIEM-101", "SIEM-102", "SIEM-103", "SIEM-104",
		"SIEM-201", "SIEM-202", "SIEM-203", "SIEM-204", "SIEM-205",
		"SIEM-301", "SIEM-302", "SIEM-303",
		"SIEM-401", "SIEM-402", "SIEM-501",
	}
	for _, ruleID := range expected {
		if !hitSet[ruleID] {
			t.Fatalf("expected %s to fire across synthetic suite; hits=%v", ruleID, hitSet)
		}
	}

	// Verify benign HTTP 200 traffic produces zero findings
	cleanEvs := []schema.Event{
		{ID: "ok-1", Timestamp: t0, Layer: "web-defense", Severity: schema.SeverityInfo, Category: "web", Action: "request", Outcome: "success", HTTPStatus: 200, SrcIP: "198.51.100.5", Host: "web-ok"},
		{ID: "ok-2", Timestamp: t0.Add(time.Second), Layer: "host-hardening", Severity: schema.SeverityInfo, Category: "auth", Action: "login", Outcome: "success", SrcIP: "198.51.100.5", Host: "web-ok", User: "dev"},
	}
	cleanFindings, _ := AnalyzeBatch(cleanEvs, policy.DefaultPolicy())
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 findings on clean events, got %+v", cleanFindings)
	}
}

func BenchmarkCorrelateEvents(b *testing.B) {
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	events := make([]schema.Event, 1000)
	for i := 0; i < 1000; i++ {
		events[i] = schema.Event{
			ID:        fmt.Sprintf("ev-%d", i),
			Timestamp: t0.Add(time.Duration(i) * time.Millisecond),
			Layer:     "web-defense",
			Severity:  schema.SeverityInfo,
			Category:  "web",
			Action:    "request",
			Outcome:   "success",
			HTTPStatus: 200,
			SrcIP:     fmt.Sprintf("198.51.100.%d", i%50),
			Host:      fmt.Sprintf("app-%02d", i%10),
		}
	}
	pol := policy.DefaultPolicy()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = AnalyzeBatch(events, pol)
	}
}
