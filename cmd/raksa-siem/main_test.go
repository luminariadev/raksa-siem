package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/ledger"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestCLIAnalyzeCleanAndAttackChainExitCodes(t *testing.T) {
	// 1. Clean fixtures -> exit 0, score 100
	var outClean, errClean bytes.Buffer
	codeClean := run([]string{"analyze", filepath.Join("..", "..", "testdata", "clean"), "--output", "json", "--fail-on", "high"}, strings.NewReader(""), &outClean, &errClean)
	if codeClean != 0 {
		t.Fatalf("expected exit 0 for testdata/clean, got %d; stderr=%s stdout=%s", codeClean, errClean.String(), outClean.String())
	}
	var cleanRep schema.Report
	if err := json.Unmarshal(outClean.Bytes(), &cleanRep); err != nil {
		t.Fatalf("unmarshal clean report: %v", err)
	}
	if cleanRep.Posture == nil || cleanRep.Posture.Score != 100 || cleanRep.Posture.Grade != "A+" {
		t.Fatalf("expected 100/A+ on clean logs, got %+v", cleanRep.Posture)
	}

	// 2. Attack chain fixtures -> exit 1, SARIF & cross-layer SIEM-201/202/204/205 present
	var outAttack, errAttack bytes.Buffer
	codeAttack := run([]string{"analyze", "--output", "sarif", "--fail-on", "high", filepath.Join("..", "..", "testdata", "attack_chain")}, strings.NewReader(""), &outAttack, &errAttack)
	if codeAttack != 1 {
		t.Fatalf("expected exit 1 for testdata/attack_chain, got %d; stderr=%s", codeAttack, errAttack.String())
	}
	if !strings.Contains(outAttack.String(), `"SIEM-201"`) || !strings.Contains(outAttack.String(), `"2.1.0"`) {
		t.Fatalf("expected SIEM-201 in SARIF 2.1.0 output: %s", outAttack.String())
	}

	// 3. Correlate subcommand on upstream JSON reports
	var outCorr, errCorr bytes.Buffer
	codeCorr := run([]string{"correlate", filepath.Join("..", "..", "testdata", "attack_chain", "raksa_netguard.json"), filepath.Join("..", "..", "testdata", "attack_chain", "raksa_pipeguard.json"), filepath.Join("..", "..", "testdata", "attack_chain", "raksa_iocscan.json"), "--output", "json"}, strings.NewReader(""), &outCorr, &errCorr)
	if codeCorr != 1 {
		t.Fatalf("expected exit 1 on cross-layer report correlation, got %d; stderr=%s", codeCorr, errCorr.String())
	}

	// 4. Rules & Version subcommands
	var outRules, errRules bytes.Buffer
	if code := run([]string{"rules", "--output", "json"}, strings.NewReader(""), &outRules, &errRules); code != 0 {
		t.Fatalf("rules failed: %d %s", code, errRules.String())
	}
	var rules []schema.RuleInfo
	if err := json.Unmarshal(outRules.Bytes(), &rules); err != nil || len(rules) != 23 {
		t.Fatalf("expected 23 rules, got %d err=%v", len(rules), err)
	}

	// 5. Verify-rules, verify-sigma & test-alert subcommands
	var outVerify, errVerify bytes.Buffer
	if code := run([]string{"verify-rules", filepath.Join("..", "..", "examples", "raksa-siem.yml"), filepath.Join("..", "..", "examples", "custom-rules.yml")}, strings.NewReader(""), &outVerify, &errVerify); code != 0 {
		t.Fatalf("verify-rules failed: %d stderr=%s", code, errVerify.String())
	}
	var outSigma, errSigma bytes.Buffer
	if code := run([]string{"verify-sigma", filepath.Join("..", "..", "testdata", "enterprise", "sigma_rules")}, strings.NewReader(""), &outSigma, &errSigma); code != 0 {
		t.Fatalf("verify-sigma failed: %d stderr=%s", code, errSigma.String())
	}
	var outAlert, errAlert bytes.Buffer
	if code := run([]string{"test-alert", "--policy", filepath.Join("..", "..", "examples", "raksa-siem.yml"), "--dry-run"}, strings.NewReader(""), &outAlert, &errAlert); code != 0 {
		t.Fatalf("test-alert failed: %d stderr=%s", code, errAlert.String())
	}

	// 6. Enterprise fixture analyze gate (Sigma + sequence + STIX/CIDR + tier1 escalation)
	var outEnt, errEnt bytes.Buffer
	codeEnt := run([]string{"analyze", filepath.Join("..", "..", "testdata", "enterprise"), "--policy", filepath.Join("..", "..", "testdata", "enterprise", "enterprise_policy.yml"), "--output", "json", "--fail-on", "high"}, strings.NewReader(""), &outEnt, &errEnt)
	if codeEnt != 1 {
		t.Fatalf("expected exit 1 on enterprise fixtures, got %d stderr=%s out=%s", codeEnt, errEnt.String(), outEnt.String())
	}
	entJSON := outEnt.String()
	for _, want := range []string{"SIEM-206", "SIEM-403", "SIEM-502", "tier1"} {
		if !strings.Contains(entJSON, want) {
			t.Fatalf("expected %q in enterprise analyze output: %s", want, entJSON)
		}
	}

	// 7. Baseline gating test
	baseFile := filepath.Join(t.TempDir(), "baseline.json")
	var outBase, errBase bytes.Buffer
	_ = run([]string{"analyze", filepath.Join("..", "..", "testdata", "attack_chain"), "--write-baseline", baseFile, "--output", "json"}, strings.NewReader(""), &outBase, &errBase)
	if _, err := os.Stat(baseFile); err != nil {
		t.Fatalf("expected baseline file created: %v", err)
	}
	var outAfterBase, errAfterBase bytes.Buffer
	codeAfterBase := run([]string{"analyze", filepath.Join("..", "..", "testdata", "attack_chain"), "--baseline", baseFile, "--output", "json"}, strings.NewReader(""), &outAfterBase, &errAfterBase)
	if codeAfterBase != 0 {
		t.Fatalf("expected exit 0 when all findings baselined, got %d; out=%s", codeAfterBase, outAfterBase.String())
	}
}

func TestCLIHTMLAttackNavLedgerAndCaseSubcommands(t *testing.T) {
	// 1. Offline HTML report
	var outHTML, errHTML bytes.Buffer
	codeHTML := run([]string{"analyze", filepath.Join("..", "..", "testdata", "attack_chain"), "--output", "html", "--fail-on", "high"}, strings.NewReader(""), &outHTML, &errHTML)
	if codeHTML != 1 {
		t.Fatalf("expected exit 1 on attack_chain html output, got %d stderr=%s", codeHTML, errHTML.String())
	}
	htmlBody := outHTML.String()
	if !strings.Contains(htmlBody, "<!DOCTYPE html>") || !strings.Contains(htmlBody, "<svg") || strings.Contains(htmlBody, "<script src=") {
		t.Fatalf("unexpected offline html report output len=%d", len(htmlBody))
	}

	// 2. MITRE ATT&CK Navigator v4.5 JSON export
	var outNav, errNav bytes.Buffer
	codeNav := run([]string{"analyze", filepath.Join("..", "..", "testdata", "attack_chain"), "--output", "attack-nav", "--fail-on", "high"}, strings.NewReader(""), &outNav, &errNav)
	if codeNav != 1 {
		t.Fatalf("expected exit 1 on attack_chain attack-nav output, got %d stderr=%s", codeNav, errNav.String())
	}
	var navDoc map[string]any
	if err := json.Unmarshal(outNav.Bytes(), &navDoc); err != nil {
		t.Fatalf("invalid attack-nav JSON: %v", err)
	}
	versions, _ := navDoc["versions"].(map[string]any)
	if versions["layer"] != "4.5" {
		t.Fatalf("expected ATT&CK Navigator layer 4.5, got %v", navDoc["versions"])
	}

	// 3. Seed ledger, update/list cases, verify clean -> 0, tamper -> 1
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	ld, err := ledger.Open(ledgerDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ld.AppendFindings([]schema.Finding{{
		ID:        "fnd-cli-1",
		RuleID:    "SIEM-001",
		Module:    "raksa-siem",
		Layer:     "siem",
		Severity:  schema.SeverityHigh,
		Title:     "SSH Burst",
		Target:    "ip://198.51.100.22",
		Timestamp: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}

	var outUpd, errUpd bytes.Buffer
	if code := run([]string{"case", "--dir", ledgerDir, "--action", "update", "--finding-id", "fnd-cli-1", "--status", "ack", "--assignee", "soc-lead", "--author", "cli-user", "--note", "escalated", "--output", "json"}, strings.NewReader(""), &outUpd, &errUpd); code != 0 {
		t.Fatalf("case update failed: %d stderr=%s", code, errUpd.String())
	}
	if !strings.Contains(outUpd.String(), `"status": "ack"`) || !strings.Contains(outUpd.String(), "escalated") {
		t.Fatalf("unexpected case update output: %s", outUpd.String())
	}

	var outList, errList bytes.Buffer
	if code := run([]string{"case", "--dir", ledgerDir, "--action", "list", "--status", "ack", "--output", "json"}, strings.NewReader(""), &outList, &errList); code != 0 {
		t.Fatalf("case list failed: %d stderr=%s", code, errList.String())
	}
	if !strings.Contains(outList.String(), "fnd-cli-1") {
		t.Fatalf("expected fnd-cli-1 in case list output: %s", outList.String())
	}

	var outVer, errVer bytes.Buffer
	if code := run([]string{"verify-ledger", "--dir", ledgerDir, "--output", "json"}, strings.NewReader(""), &outVer, &errVer); code != 0 {
		t.Fatalf("verify-ledger clean failed: %d stderr=%s out=%s", code, errVer.String(), outVer.String())
	}
	if !strings.Contains(outVer.String(), `"valid": true`) {
		t.Fatalf("expected valid:true in verify-ledger output: %s", outVer.String())
	}

	// Tamper 1 byte in ledger segment and assert verify-ledger returns exit 1
	segs, err := filepath.Glob(filepath.Join(ledgerDir, "siem-*.ndjson"))
	if err != nil || len(segs) == 0 {
		t.Fatalf("expected ledger segment file: err=%v segs=%v", err, segs)
	}
	rawSeg, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(rawSeg), "escalated", "escalateX", 1)
	if err := os.WriteFile(segs[0], []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}

	var outBad, errBad bytes.Buffer
	if code := run([]string{"verify-ledger", "--dir", ledgerDir, "--output", "table"}, strings.NewReader(""), &outBad, &errBad); code != 1 {
		t.Fatalf("expected exit 1 after ledger tamper, got %d out=%s stderr=%s", code, outBad.String(), errBad.String())
	}
	if !strings.Contains(outBad.String(), "INVALID") {
		t.Fatalf("expected INVALID status in verify-ledger table output: %s", outBad.String())
	}
}
