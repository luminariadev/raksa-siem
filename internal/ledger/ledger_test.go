package ledger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestLedgerAppendSearchCaseAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()

	// Create an old expired segment that retentionDays=7 must remove cleanly before creating active chain
	stalePath := filepath.Join(dir, "siem-2020-01-01.ndjson")
	if err := os.WriteFile(stalePath, []byte(`{"bad":"stale"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := Open(dir, 7)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if _, statErr := os.Stat(stalePath); !os.IsNotExist(statErr) {
		t.Fatalf("expected retention=7 to prune %s", stalePath)
	}

	ev1 := schema.Event{
		ID: "ev-1", Timestamp: now.Add(-2 * time.Minute), Layer: "host-hardening",
		Severity: schema.SeverityMedium, Category: "auth", Action: "login", Outcome: "failure",
		SrcIP: "198.51.100.88", Host: "prod-core-01", User: "admin", Message: "Failed password",
	}
	f1 := schema.Finding{
		ID: "siem-001-abcd", RuleID: "SIEM-001", Module: "auth", Layer: schema.LayerName,
		Severity: schema.SeverityHigh, Title: "Brute force", Description: "SSH burst",
		Target: "ip://198.51.100.88", Evidence: map[string]any{"src_ip": "198.51.100.88"},
		MitreD3FEND: "D3-UAL", Timestamp: now.Add(-time.Minute),
	}

	if err := l.AppendEvents([]schema.Event{ev1}); err != nil {
		t.Fatalf("AppendEvents: %v", err)
	}
	if err := l.AppendFindings([]schema.Finding{f1}); err != nil {
		t.Fatalf("AppendFindings: %v", err)
	}

	rec, err := l.UpdateCase("siem-001-abcd", "ack", "soc-lead", "alice", "Investigating source subnet")
	if err != nil || rec.Status != StatusAck || len(rec.Notes) != 1 {
		t.Fatalf("UpdateCase failed: %+v err=%v", rec, err)
	}
	if _, err := l.UpdateCase("siem-001-abcd", "invalid_state", "", "", ""); err == nil {
		t.Fatal("expected fail-closed error on invalid case status")
	}

	searchRes, err := l.Search(SearchQuery{SrcIP: "198.51.100.88", Kind: "finding"})
	if err != nil || len(searchRes.Findings) != 1 || searchRes.Findings[0].ID != "siem-001-abcd" {
		t.Fatalf("Search unexpected: %+v err=%v", searchRes, err)
	}

	vRep, err := l.Verify()
	if err != nil || !vRep.Valid || vRep.EntriesChecked != 3 || vRep.SegmentsChecked == 0 {
		t.Fatalf("expected valid 3-entry ledger, got %+v err=%v", vRep, err)
	}

	// Re-open ledger from disk to verify persistence and case snapshot reconstruction
	reopened, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("reopen Open failed: %v", err)
	}
	gotCase, ok := reopened.GetCase("siem-001-abcd")
	if !ok || gotCase.Status != StatusAck || gotCase.Assignee != "soc-lead" {
		t.Fatalf("expected persisted ack case on reload, got %+v ok=%v", gotCase, ok)
	}

	// Tamper 1 byte inside segment and verify detection fails closed!
	segs, _ := listSegmentFiles(dir)
	rawSeg, _ := os.ReadFile(segs[0])
	tampered := strings.Replace(string(rawSeg), "Failed password", "Edited password", 1)
	if err := os.WriteFile(segs[0], []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperRep, err := VerifyDir(dir)
	if err != nil || tamperRep.Valid || tamperRep.BrokenAtSeq != 1 {
		t.Fatalf("expected tamper detection at seq 1, got %+v err=%v", tamperRep, err)
	}
	if _, err := Open(dir, 0); err == nil {
		t.Fatal("expected Open on tampered ledger to fail closed")
	}
}

func BenchmarkLedgerAppendAndVerify(b *testing.B) {
	dir := b.TempDir()
	l, err := Open(dir, 0)
	if err != nil {
		b.Fatal(err)
	}
	ev := schema.Event{
		ID: "bench", Timestamp: time.Now().UTC(), Layer: "web-defense",
		Severity: schema.SeverityInfo, Category: "web", Action: "request", Outcome: "success",
		SrcIP: "198.51.100.10", Host: "edge-01",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.ID = fmt.Sprintf("ev-%d", i)
		if err := l.AppendEvents([]schema.Event{ev}); err != nil {
			b.Fatal(err)
		}
	}
}
