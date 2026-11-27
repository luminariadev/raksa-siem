package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if err := json.Unmarshal(outRules.Bytes(), &rules); err != nil || len(rules) != 20 {
		t.Fatalf("expected 20 rules, got %d err=%v", len(rules), err)
	}

	// 5. Verify-rules & test-alert subcommands
	var outVerify, errVerify bytes.Buffer
	if code := run([]string{"verify-rules", filepath.Join("..", "..", "examples", "raksa-siem.yml"), filepath.Join("..", "..", "examples", "custom-rules.yml")}, strings.NewReader(""), &outVerify, &errVerify); code != 0 {
		t.Fatalf("verify-rules failed: %d stderr=%s", code, errVerify.String())
	}
	var outAlert, errAlert bytes.Buffer
	if code := run([]string{"test-alert", "--policy", filepath.Join("..", "..", "examples", "raksa-siem.yml"), "--dry-run"}, strings.NewReader(""), &outAlert, &errAlert); code != 0 {
		t.Fatalf("test-alert failed: %d stderr=%s", code, errAlert.String())
	}

	// 6. Baseline gating test
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
