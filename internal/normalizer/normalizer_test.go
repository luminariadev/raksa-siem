package normalizer

import (
	"strings"
	"testing"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestParseAllSevenFormatsAndMalformedTolerance(t *testing.T) {
	// 1. Pretty-printed Raksa Report JSON envelope
	raksaReport := `{
  "schema_version": "1.0",
  "tool": "raksa-netguard",
  "layer": "network-defense",
  "findings": [
    {
      "id": "net-101-1",
      "rule_id": "NET-101",
      "module": "anomaly",
      "layer": "network-defense",
      "severity": "high",
      "title": "Vertical port scan",
      "description": "Scan from 198.51.100.44",
      "target": "host://edge-01",
      "evidence": {"src_ip": "198.51.100.44", "port": 22},
      "remediation": "Block IP",
      "mitre_d3fend": "D3-NTA",
      "timestamp": "2026-11-27T10:00:00Z"
    }
  ]
}`
	evs, stats, err := ParseBytes([]byte(raksaReport), FormatAuto, "net.json")
	if err != nil || len(evs) != 1 || stats.ByFormat[FormatRaksa] != 1 {
		t.Fatalf("unexpected raksa envelope parse: err=%v evs=%d stats=%+v", err, len(evs), stats)
	}
	if evs[0].SrcIP != "198.51.100.44" || evs[0].Host != "edge-01" || evs[0].DstPort != 22 {
		t.Fatalf("unexpected extracted fields: %+v", evs[0])
	}

	// 2. Mixed line-delimited formats (raksa-ndjson, auth.log, syslog, nginx, jsonl, cef, + malformed line)
	mixed := strings.Join([]string{
		`{"id":"ioc-1","rule_id":"IOC-202","module":"static","layer":"ioc-defense","severity":"critical","title":"ELF masquerade","description":"Dropped binary","target":"file:///tmp/bad.pdf","evidence":{"host":"edge-01","src_ip":"198.51.100.44"},"remediation":"Quarantine","mitre_d3fend":"D3-FA","timestamp":"2026-11-27T10:01:00Z"}`,
		`Nov 27 10:01:05 edge-01 sshd[1020]: Failed password for invalid user admin from 198.51.100.44 port 55100 ssh2`,
		`Nov 27 10:01:10 edge-01 sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash`,
		`<38>1 2026-11-27T10:01:15Z edge-01 rsyslogd 222 - - history -c executed before exit`,
		`198.51.100.44 - - [27/Nov/2026:10:01:20 +0000] "GET /../../etc/passwd HTTP/1.1" 403 512 "-" "sqlmap/1.7" host=edge-01`,
		`{"timestamp":"2026-11-27T10:01:25Z","src_ip":"198.51.100.44","host":"edge-01","layer":"devsecops","category":"telemetry","action":"deploy","outcome":"ok","severity":"low","message":"generic jsonl line"}`,
		`Nov 27 10:01:30 edge-01 CEF:0|Raksa|WebWAF|1.0|WEB-101|SQLi Probe|8|src=198.51.100.44 dhost=edge-01 request=/login msg=blocked payload`,
		`this line is intentionally unparseable garbage without syslog headers`,
	}, "\n")

	mEvs, mStats, err := ParseBytes([]byte(mixed), FormatAuto, "mixed.log")
	if err != nil {
		t.Fatalf("mixed parse error: %v", err)
	}
	if len(mEvs) != 7 || mStats.SkippedLines != 1 {
		t.Fatalf("expected 7 parsed events and 1 skipped line, got %d (%+v)", len(mEvs), mStats)
	}
	if mEvs[0].SourceFormat != FormatRaksaNDJSON || mEvs[0].Severity != schema.SeverityCritical {
		t.Fatalf("unexpected raksa-ndjson event: %+v", mEvs[0])
	}
	if mEvs[1].Action != "login" || mEvs[1].Outcome != "failure" || mEvs[1].User != "admin" {
		t.Fatalf("unexpected sshd auth event: %+v", mEvs[1])
	}
	if mEvs[2].Category != "privilege" || mEvs[2].Severity != schema.SeverityHigh {
		t.Fatalf("unexpected sudo privilege event: %+v", mEvs[2])
	}
	if mEvs[3].Action != "log_tamper" || mEvs[3].Severity != schema.SeverityMedium {
		t.Fatalf("unexpected syslog tamper event: %+v", mEvs[3])
	}
	if mEvs[4].Action != "probe" || mEvs[4].Outcome != "blocked" || mEvs[4].Host != "edge-01" {
		t.Fatalf("unexpected nginx probe event: %+v", mEvs[4])
	}
	if mEvs[5].SourceFormat != FormatJSONL {
		t.Fatalf("unexpected jsonl event: %+v", mEvs[5])
	}
	if mEvs[6].SourceFormat != FormatCEF || mEvs[6].Severity != schema.SeverityHigh || mEvs[6].SrcIP != "198.51.100.44" {
		t.Fatalf("unexpected cef event: %+v", mEvs[6])
	}
}

func BenchmarkNormalizeMixed(b *testing.B) {
	line := []byte(strings.Repeat(
		`198.51.100.44 - - [27/Nov/2026:10:01:20 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0" host=edge-01`+"\n"+
			`Nov 27 10:01:05 edge-01 sshd[1020]: Failed password for admin from 198.51.100.44 port 55100 ssh2`+"\n",
		500,
	))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		evs, _, err := ParseBytes(line, FormatAuto, "bench.log")
		if err != nil || len(evs) != 1000 {
			b.Fatalf("bench parse failed: err=%v len=%d", err, len(evs))
		}
	}
}
