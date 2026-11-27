package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestSanitizeAndMultiFormatReport(t *testing.T) {
	dirty := "evil\x1b[31mred\x1b[0m\x1b]0;title\x07\x85next"
	clean := SanitizeTerminal(dirty)
	if strings.ContainsRune(clean, 0x1b) || clean != "evilrednext" {
		t.Fatalf("unexpected sanitized output: %q", clean)
	}

	rep := schema.NewReport([]schema.Finding{
		{
			ID:          "siem-002-1",
			RuleID:      "SIEM-002",
			Module:      "auth",
			Layer:       schema.LayerName,
			Severity:    schema.SeverityCritical,
			Title:       "Brute-force followed by login",
			Description: "Source IP 198.51.100.10 succeeded after failures",
			Target:      "host://bastion-01",
			Evidence:    map[string]any{"src_ip": "198.51.100.10"},
			Remediation: "Revoke active SSH sessions and block source IP.",
			MitreD3FEND: "D3-UAL",
			Timestamp:   time.Unix(1732700000, 0).UTC(),
		},
	})

	tbl, err := FormatReport(rep, FormatTable)
	if err != nil || !strings.Contains(tbl, "70/100 (C)") || !strings.Contains(tbl, "SIEM-002") {
		t.Fatalf("unexpected table render: err=%v tbl=%s", err, tbl)
	}

	jsOut, err := FormatReport(rep, FormatJSON)
	if err != nil {
		t.Fatalf("json format failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsOut), &parsed); err != nil || parsed["tool"] != "raksa-siem" {
		t.Fatalf("invalid json report: %v", err)
	}

	sarifOut, err := FormatReport(rep, FormatSARIF)
	if err != nil {
		t.Fatalf("sarif format failed: %v", err)
	}
	var sarifObj struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(sarifOut), &sarifObj); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if sarifObj.Version != "2.1.0" || len(sarifObj.Runs[0].Tool.Driver.Rules) != 20 || len(sarifObj.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif structure: %+v", sarifObj)
	}

	mdOut, err := FormatReport(rep, FormatMarkdown)
	if err != nil || !strings.Contains(mdOut, "Raksa SIEM Security Report") {
		t.Fatalf("unexpected markdown output: %v", err)
	}

	ndOut, err := FormatReport(rep, FormatNDJSON)
	if err != nil || len(strings.Split(strings.TrimSpace(ndOut), "\n")) != 1 {
		t.Fatalf("unexpected ndjson output: err=%v out=%q", err, ndOut)
	}
}
