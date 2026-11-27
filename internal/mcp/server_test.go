package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-siem/internal/policy"
)

func TestMCPServeAllEightTools(t *testing.T) {
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
	)

	var out bytes.Buffer
	if err := srv.Serve(strings.NewReader(strings.Join(reqs, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected 7 JSON-RPC responses (notification omitted), got %d: %s", len(lines), out.String())
	}

	// Verify 8 tools listed
	var listResp struct {
		Result struct {
			Tools []toolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil || len(listResp.Result.Tools) != 8 {
		t.Fatalf("expected 8 MCP tools, got %d err=%v", len(listResp.Result.Tools), err)
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
}
