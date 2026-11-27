package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/ledger"
	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestMCPServeAllTwelveTools(t *testing.T) {
	dir := t.TempDir()
	sigmaFile := filepath.Join(dir, "sigma.yml")
	_ = os.WriteFile(sigmaFile, []byte("title: MCP Sigma Probe\nid: SIG-M1\nlevel: high\ndetection:\n  sel:\n    category: ops\n  condition: sel\n"), 0o600)
	intelFile := filepath.Join(dir, "intel.txt")
	_ = os.WriteFile(intelFile, []byte("198.51.100.50\n"), 0o600)
	ledgerDir := filepath.Join(dir, "ledger")
	ld, err := ledger.Open(ledgerDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ld.AppendFindings([]schema.Finding{{
		ID:        "fnd-mcp-1",
		RuleID:    "SIEM-001",
		Module:    "raksa-siem",
		Layer:     "siem",
		Severity:  schema.SeverityHigh,
		Title:     "SSH Burst",
		Target:    "ip://198.51.100.50",
		Timestamp: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}

	pol := policy.DefaultPolicy()
	pol.AuthBurstThreshold = 3
	srv := New(pol)

	var reqs []string
	mustMarshal := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// 1. initialize + notification + ping
	reqs = append(reqs,
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "siem_list_rules", "arguments": map[string]any{}}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{
			"name": "siem_analyze_logs",
			"arguments": map[string]any{
				"format": "auth",
				"content": strings.Join([]string{
					"Nov 27 10:00:01 bastion-01 sshd[10]: Failed password for root from 198.51.100.50 port 5000 ssh2",
					"Nov 27 10:00:02 bastion-01 sshd[11]: Failed password for root from 198.51.100.50 port 5001 ssh2",
					"Nov 27 10:00:03 bastion-01 sshd[12]: Failed password for root from 198.51.100.50 port 5002 ssh2",
				}, "\n"),
			},
		}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]any{
			"name":      "siem_check_suppression",
			"arguments": map[string]any{"rule_id": "SIEM-001", "group_key": "ip://198.51.100.50"},
		}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": map[string]any{
			"name":      "siem_check_suppression",
			"arguments": map[string]any{"rule_id": "SIEM-001", "group_key": "ip://198.51.100.50"},
		}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{
			"name":      "siem_query_incidents",
			"arguments": map[string]any{"rule_id": "SIEM-001"},
		}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": map[string]any{
			"name":      "siem_verify_sigma",
			"arguments": map[string]any{"path": sigmaFile},
		}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": map[string]any{
			"name": "siem_match_threat_intel",
			"arguments": map[string]any{
				"threat_intel_paths": []string{intelFile},
				"src_ip":             "198.51.100.50",
			},
		}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": map[string]any{
			"name": "siem_triage_case",
			"arguments": map[string]any{
				"dir":        ledgerDir,
				"finding_id": "fnd-mcp-1",
				"status":     "resolved",
				"assignee":   "secops",
				"author":     "mcp-bot",
				"note":       "blocked at perimeter",
			},
		}}),
		mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": map[string]any{
			"name":      "siem_verify_ledger",
			"arguments": map[string]any{"dir": ledgerDir},
		}}),
	)

	var out bytes.Buffer
	if err := srv.Serve(strings.NewReader(strings.Join(reqs, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 11 {
		t.Fatalf("expected 11 JSON-RPC responses (notification omitted), got %d: %s", len(lines), out.String())
	}

	// Verify 12 tools listed
	var listResp struct {
		Result struct {
			Tools []toolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil || len(listResp.Result.Tools) != 12 {
		t.Fatalf("expected 12 MCP tools, got %d err=%v", len(listResp.Result.Tools), err)
	}

	// Verify analyze returned SIEM-001, suppression 1st allowed 2nd suppressed, query found SIEM-001
	if !strings.Contains(lines[3], "SIEM-001") {
		t.Fatalf("expected SIEM-001 in siem_analyze_logs response: %s", lines[3])
	}
	if !strings.Contains(lines[4], `\"suppressed\": false`) {
		t.Fatalf("expected first siem_check_suppression deliver=true/suppressed=false: %s", lines[4])
	}
	if !strings.Contains(lines[5], `\"suppressed\": true`) {
		t.Fatalf("expected second siem_check_suppression suppressed=true: %s", lines[5])
	}
	if !strings.Contains(lines[6], "SIEM-001") {
		t.Fatalf("expected SIEM-001 in siem_query_incidents: %s", lines[6])
	}
	if !strings.Contains(lines[7], "SIG-M1") {
		t.Fatalf("expected SIG-M1 in siem_verify_sigma: %s", lines[7])
	}
	if !strings.Contains(lines[8], "198.51.100.50") {
		t.Fatalf("expected 198.51.100.50 in siem_match_threat_intel: %s", lines[8])
	}
	if !strings.Contains(lines[9], "resolved") || !strings.Contains(lines[9], "blocked at perimeter") {
		t.Fatalf("expected resolved status and note in siem_triage_case: %s", lines[9])
	}
	if !strings.Contains(lines[10], `\"valid\": true`) {
		t.Fatalf("expected valid=true in siem_verify_ledger: %s", lines[10])
	}

	// Tamper a segment file and ensure siem_verify_ledger reports valid=false without transport error
	segs, err := filepath.Glob(filepath.Join(ledgerDir, "siem-*.ndjson"))
	if err != nil || len(segs) == 0 {
		t.Fatalf("expected ledger segment file: err=%v segs=%v", err, segs)
	}
	rawSeg, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(rawSeg), "blocked at perimeter", "blocked at perimetXr", 1)
	if err := os.WriteFile(segs[0], []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	var outTamper bytes.Buffer
	tamperReq := mustMarshal(map[string]any{"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": map[string]any{
		"name":      "siem_verify_ledger",
		"arguments": map[string]any{"dir": ledgerDir},
	}})
	if err := srv.Serve(strings.NewReader(tamperReq+"\n"), &outTamper); err != nil {
		t.Fatalf("Serve tamper failed: %v", err)
	}
	if !strings.Contains(outTamper.String(), `\"valid\": false`) {
		t.Fatalf("expected valid=false after tamper in siem_verify_ledger: %s", outTamper.String())
	}
}
