package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-siem/internal/policy"
)

func TestMCPServeAllTenTools(t *testing.T) {
	dir := t.TempDir()
	sigmaFile := filepath.Join(dir, "sigma.yml")
	_ = os.WriteFile(sigmaFile, []byte("title: MCP Sigma Probe\nid: SIG-M1\nlevel: high\ndetection:\n  sel:\n    category: ops\n  condition: sel\n"), 0o600)
	intelFile := filepath.Join(dir, "intel.txt")
	_ = os.WriteFile(intelFile, []byte("198.51.100.50\n"), 0o600)

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
	)

	var out bytes.Buffer
	if err := srv.Serve(strings.NewReader(strings.Join(reqs, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 9 {
		t.Fatalf("expected 9 JSON-RPC responses (notification omitted), got %d: %s", len(lines), out.String())
	}

	// Verify 10 tools listed
	var listResp struct {
		Result struct {
			Tools []toolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil || len(listResp.Result.Tools) != 10 {
		t.Fatalf("expected 10 MCP tools, got %d err=%v", len(listResp.Result.Tools), err)
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
}
