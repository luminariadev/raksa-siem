package sigma

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestSigmaCompilerModifiersBooleanAndAggregation(t *testing.T) {
	b64Payload := base64.StdEncoding.EncodeToString([]byte("xx raksa_b64_probe --exec"))

	yamlDocs := `---
title: Suspicious Encoded Shell Execution
id: SIGMA-001
level: critical
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
detection:
  selection_cmd:
    CommandLine|contains|all:
      - powershell
      - -enc
  selection_b64:
    CommandLine|base64:
      - "raksa_b64_probe"
  filter_local:
    SourceIp|cidr:
      - 10.0.0.0/8
  condition: selection_cmd and selection_b64 and not filter_local
---
title: CloudTrail StopLogging Tamper
id: SIGMA-002
level: high
logsource:
  product: aws
  service: cloudtrail
detection:
  sel_event:
    eventSource: cloudtrail.amazonaws.com
    eventName:
      - StopLogging
      - DeleteTrail
  condition: 1 of sel_*
---
title: Multi-Document Auth Burst Count
id: SIGMA-003
level: medium
detection:
  selection:
    category: auth
    outcome: failure
  condition: selection | count() by src_ip >= 5
  timeframe: 10m
`

	rules, err := ParseBytes([]byte(yamlDocs), "suite.yml")
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if rules[0].MitreTechnique != "T1059" || rules[0].Level != schema.SeverityCritical {
		t.Fatalf("unexpected MITRE/level metadata: %+v", rules[0])
	}
	if !rules[2].HasAggregation() || rules[2].Aggregation.GroupBy != "src_ip" || rules[2].Aggregation.Threshold != 5 {
		t.Fatalf("unexpected aggregation spec: %+v", rules[2].Aggregation)
	}

	evMatch := schema.Event{
		ID:       "e1",
		Category: "process",
		Action:   "exec",
		SrcIP:    "198.51.100.66",
		Metadata: map[string]any{
			"command_line": "powershell -enc " + b64Payload,
		},
	}
	if !rules[0].MatchesEvent(evMatch) {
		t.Fatal("expected SIGMA-001 to match encoded powershell execution from RFC 5737 IP")
	}

	evFiltered := evMatch
	evFiltered.SrcIP = "10.20.30.40"
	if rules[0].MatchesEvent(evFiltered) {
		t.Fatal("expected CIDR filter_local (10.0.0.0/8) to suppress match")
	}

	evCloud := schema.Event{
		ID:           "e2",
		SourceFormat: "cloudtrail",
		Layer:        "cloud-audit",
		Action:       "log_tamper",
		Metadata: map[string]any{
			"event_source": "cloudtrail.amazonaws.com",
			"event_name":   "StopLogging",
		},
	}
	if !rules[1].MatchesEvent(evCloud) {
		t.Fatal("expected SIGMA-002 to match CloudTrail StopLogging event")
	}

	// Fail-closed on invalid regex or invalid condition identifier
	badRegex := `
title: Bad Regex
detection:
  sel:
    message|re: "[unclosed"
  condition: sel
`
	if _, err := ParseBytes([]byte(badRegex), "bad.yml"); err == nil {
		t.Fatal("expected ParseBytes to fail closed on invalid regex")
	}
	badCond := `
title: Missing Selection Ref
detection:
  sel:
    message: "ok"
  condition: sel and unknown_sel
`
	if _, err := ParseBytes([]byte(badCond), "badcond.yml"); err == nil {
		t.Fatal("expected ParseBytes to fail closed on unknown selection ref")
	}
}

func BenchmarkSigmaEval(b *testing.B) {
	yamlRule := strings.Join([]string{
		`title: Benchmark Rule`,
		`id: SIGMA-BENCH`,
		`level: high`,
		`detection:`,
		`  sel:`,
		`    CommandLine|contains: "/opt/raksa/bench_probe"`,
		`    SourceIp|cidr: "198.51.100.0/24"`,
		`  condition: sel`,
	}, "\n")
	rules, err := ParseBytes([]byte(yamlRule), "bench.yml")
	if err != nil {
		b.Fatal(err)
	}
	r := rules[0]
	ev := schema.Event{
		ID:        "b1",
		Timestamp: time.Now().UTC(),
		SrcIP:     "198.51.100.66",
		Metadata:  map[string]any{"command_line": "/opt/raksa/bench_probe --target 198.51.100.66 --port 4444"},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !r.MatchesEvent(ev) {
			b.Fatal("expected match")
		}
	}
}
