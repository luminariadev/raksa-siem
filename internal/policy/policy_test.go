package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestPolicyValidationFailClosedAndBaselines(t *testing.T) {
	dir := t.TempDir()

	// Missing reason -> fail closed
	badSup := filepath.Join(dir, "bad-reason.yml")
	_ = os.WriteFile(badSup, []byte("suppressions:\n  - rule_id: SIEM-001\n    expires_on: \"2028-12-31\"\n"), 0o600)
	if _, err := LoadPolicy(badSup); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("expected fail-closed error for missing reason, got: %v", err)
	}

	// Expired waiver -> fail closed
	expiredSup := filepath.Join(dir, "expired.yml")
	_ = os.WriteFile(expiredSup, []byte("suppressions:\n  - rule_id: SIEM-001\n    reason: \"old test\"\n    expires_on: \"2020-01-01\"\n"), 0o600)
	if _, err := LoadPolicy(expiredSup); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected fail-closed error for expired waiver, got: %v", err)
	}

	// Non-HTTPS external webhook route -> fail closed
	badRoute := filepath.Join(dir, "bad-route.yml")
	_ = os.WriteFile(badRoute, []byte("routes:\n  - name: ext\n    type: webhook\n    url: http://hooks.example.com/alert\n"), 0o600)
	if _, err := LoadPolicy(badRoute); err == nil || !strings.Contains(err.Error(), "HTTPS required") {
		t.Fatalf("expected HTTPS error, got: %v", err)
	}

	// Valid policy with suppression + custom rule + route
	validPath := filepath.Join(dir, ".raksa-siem.yml")
	validYAML := `
min_severity: medium
suppression_window: 5m
watched_ips:
  - 203.0.113.55
suppressions:
  - rule_id: SIEM-501
    target_contains: "198.51.100.1"
    reason: "Authorized pentest lab bastion"
    expires_on: "2028-12-31"
custom_rules:
  - id: ORG-SUDO-01
    title: "Detect suspicious curl inside sudo"
    severity: high
    match:
      category: privilege
      contains: curl
routes:
  - name: local-dev
    type: webhook
    url: http://127.0.0.1:8080/hook
    min_severity: high
`
	_ = os.WriteFile(validPath, []byte(validYAML), 0o600)
	pol, discovered, err := DiscoverPolicy(dir, "")
	if err != nil || discovered == "" {
		t.Fatalf("discover failed: %v", err)
	}
	if len(pol.CustomRules) != 1 || len(pol.Routes) != 1 {
		t.Fatalf("unexpected parsed policy: %+v", pol)
	}

	findings := []schema.Finding{
		{ID: "1", RuleID: "SIEM-303", Severity: schema.SeverityLow, Target: "host://a"},
		{ID: "2", RuleID: "SIEM-501", Severity: schema.SeverityMedium, Target: "ip://198.51.100.1"},
		{ID: "3", RuleID: "SIEM-001", Severity: schema.SeverityHigh, Target: "ip://198.51.100.99"},
	}
	kept, supCount := ApplyPolicy(findings, pol)
	if len(kept) != 1 || supCount != 2 || kept[0].RuleID != "SIEM-001" {
		t.Fatalf("unexpected ApplyPolicy result: kept=%+v sup=%d", kept, supCount)
	}

	baseFile := filepath.Join(dir, "baseline.json")
	if err := WriteBaseline(baseFile, kept); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	base, err := LoadBaseline(baseFile)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	afterBase, baseSup := ApplyBaseline(kept, base)
	if len(afterBase) != 0 || baseSup != 1 {
		t.Fatalf("unexpected baseline filtering: len=%d sup=%d", len(afterBase), baseSup)
	}
}
