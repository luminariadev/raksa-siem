package schema

import (
	"testing"
	"time"
)

func TestRuleCatalogAndPostureScoring(t *testing.T) {
	rules := RuleCatalog()
	if len(rules) != 23 {
		t.Fatalf("expected 23 built-in rules, got %d", len(rules))
	}

	seen := make(map[string]bool)
	for _, r := range rules {
		if seen[r.RuleID] {
			t.Fatalf("duplicate rule id %q", r.RuleID)
		}
		seen[r.RuleID] = true
		if r.MitreD3FEND == "" || r.Title == "" || r.Description == "" {
			t.Fatalf("incomplete metadata on rule %s", r.RuleID)
		}
	}

	if got := RuleCatalog("auth"); len(got) != 5 {
		t.Fatalf("expected 5 auth rules, got %d", len(got))
	}
	for _, rid := range []string{"SIEM-201", "SIEM-206", "SIEM-403", "SIEM-502"} {
		if _, ok := LookupRule(rid); !ok {
			t.Fatalf("expected %s in catalog", rid)
		}
	}

	clean := ComputePosture(nil)
	if clean.Score != 100 || clean.Grade != "A+" {
		t.Fatalf("unexpected clean posture: %+v", clean)
	}

	findings := []Finding{
		{ID: "1", RuleID: "SIEM-002", Severity: SeverityCritical, Timestamp: time.Now().UTC()},
		{ID: "2", RuleID: "SIEM-001", Severity: SeverityHigh, Timestamp: time.Now().UTC()},
	}
	posture := ComputePosture(findings)
	if posture.Score != 52 || posture.Grade != "F" {
		t.Fatalf("expected 52/F, got %+v", posture)
	}

	sev, err := ParseSeverity("HIGH")
	if err != nil || sev != SeverityHigh || !sev.MeetsThreshold(SeverityMedium) {
		t.Fatalf("unexpected severity behavior: %v %v", sev, err)
	}
}
