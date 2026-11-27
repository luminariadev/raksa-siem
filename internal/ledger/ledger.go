package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

const (
	// GenesisHash is the 64-zero PrevHash linking the first entry in a ledger chain.
	GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

	maxLineBytes = 4 << 20 // 4 MiB per NDJSON segment line
)

// CaseStatus constants govern allowed incident triage lifecycle transitions.
const (
	StatusOpen          = "open"
	StatusAck           = "ack"
	StatusResolved      = "resolved"
	StatusFalsePositive = "false_positive"
)

// ParseCaseStatus validates and normalizes an incident case status string (fail-closed).
func ParseCaseStatus(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case StatusOpen:
		return StatusOpen, nil
	case StatusAck, "acknowledged", "in_progress":
		return StatusAck, nil
	case StatusResolved, "closed":
		return StatusResolved, nil
	case StatusFalsePositive, "fp":
		return StatusFalsePositive, nil
	default:
		return "", fmt.Errorf("invalid case status %q: expected open, ack, resolved, or false_positive", raw)
	}
}

// CaseNote captures one timestamped analyst comment attached to an incident case.
type CaseNote struct {
	Author    string `json:"author"`
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
}

// CaseRecord tracks triage status, assignment, and analyst notes for one Finding ID.
type CaseRecord struct {
	FindingID string     `json:"finding_id"`
	Status    string     `json:"status"`
	Assignee  string     `json:"assignee,omitempty"`
	UpdatedAt string     `json:"updated_at"`
	Notes     []CaseNote `json:"notes,omitempty"`
}

// CaseTransition is the immutable payload recorded into the hash chain when updating a case.
type CaseTransition struct {
	FindingID string `json:"finding_id"`
	Status    string `json:"status"`
	Assignee  string `json:"assignee,omitempty"`
	Author    string `json:"author,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Entry represents one hash-chained audit record stored inside siem-YYYY-MM-DD.ndjson segments.
// Payload MUST remain last so exact raw payload bytes verify cleanly across languages.
type Entry struct {
	Seq       uint64          `json:"seq"`
	Timestamp string          `json:"timestamp"`
	Kind      string          `json:"kind"` // event, finding, case_update
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
	Payload   json.RawMessage `json:"payload"`
}

// SearchQuery filters indexed historical ledger segments cleanly by time bounds and predicates.
type SearchQuery struct {
	From     time.Time `json:"from,omitempty"`
	To       time.Time `json:"to,omitempty"`
	Kind     string    `json:"kind,omitempty"`     // event, finding, case_update, or "" (events+findings)
	Query    string    `json:"query,omitempty"`    // case-insensitive substring filter
	Severity string    `json:"severity,omitempty"` // minimum severity for findings/events
	RuleID   string    `json:"rule_id,omitempty"`
	Layer    string    `json:"layer,omitempty"`
	Host     string    `json:"host,omitempty"`
	SrcIP    string    `json:"src_ip,omitempty"`
	User     string    `json:"user,omitempty"`
	Limit    int       `json:"limit,omitempty"`
}

// SearchResult aggregates matching historical entries returned by Search.
type SearchResult struct {
	Total    int              `json:"total"`
	Events   []schema.Event   `json:"events,omitempty"`
	Findings []schema.Finding `json:"findings,omitempty"`
}

// VerifyReport summarizes SHA-256 hash-chain verification over an entire ledger directory.
type VerifyReport struct {
	Valid           bool   `json:"valid"`
	Dir             string `json:"dir"`
	SegmentsChecked int    `json:"segments_checked"`
	EntriesChecked  uint64 `json:"entries_checked"`
	TipHash         string `json:"tip_hash"`
	BrokenSegment   string `json:"broken_segment,omitempty"`
	BrokenAtSeq     uint64 `json:"broken_at_seq,omitempty"`
	Error           string `json:"error,omitempty"`
}

// ComputeEntryHash computes SHA-256 over canonical entry fields and exact compact payload bytes.
func ComputeEntryHash(seq uint64, tsStr, kind, prevHash string, compactPayload []byte) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d|%s|%s|%s|", seq, tsStr, kind, prevHash)
	h.Write(compactPayload)
	return hex.EncodeToString(h.Sum(nil))
}

// Ledger manages append-only date-segmented NDJSON logs chained by SHA-256 plus incident cases.
type Ledger struct {
	mu            sync.Mutex
	dir           string
	retentionDays int
	nextSeq       uint64
	tipHash       string
	cases         map[string]CaseRecord
}

// Open initializes or reloads a segmented hash-chained Ledger at dir.
// If retentionDays > 0, segments strictly older than retentionDays are removed at startup.
func Open(dir string, retentionDays int) (*Ledger, error) {
	cleanDir := filepath.Clean(dir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return nil, fmt.Errorf("create ledger dir %q: %w", cleanDir, err)
	}

	l := &Ledger{
		dir:           cleanDir,
		retentionDays: retentionDays,
		nextSeq:       1,
		tipHash:       GenesisHash,
		cases:         make(map[string]CaseRecord),
	}

	if retentionDays > 0 {
		_ = l.pruneOldSegmentsLocked(time.Now().UTC())
	}

	rep, err := l.reloadStateLocked()
	if err != nil {
		return nil, err
	}
	if !rep.Valid {
		return nil, fmt.Errorf("ledger integrity failure at %s seq %d: %s", rep.BrokenSegment, rep.BrokenAtSeq, rep.Error)
	}
	return l, nil
}

func (l *Ledger) reloadStateLocked() (VerifyReport, error) {
	segments, err := listSegmentFiles(l.dir)
	if err != nil {
		return VerifyReport{}, err
	}
	rep := VerifyReport{
		Valid:           true,
		Dir:             l.dir,
		SegmentsChecked: len(segments),
		TipHash:         GenesisHash,
	}

	expectedSeq := uint64(1)
	expectedPrev := GenesisHash

	for _, segPath := range segments {
		f, err := os.Open(segPath)
		if err != nil {
			return VerifyReport{}, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), maxLineBytes)
		for sc.Scan() {
			rawLine := strings.TrimSpace(sc.Text())
			if rawLine == "" {
				continue
			}
			var ent Entry
			if err := json.Unmarshal([]byte(rawLine), &ent); err != nil {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = expectedSeq
				rep.Error = fmt.Sprintf("corrupt JSON at seq %d: %v", expectedSeq, err)
				return rep, nil
			}
			compactPayload, err := compactBytes(ent.Payload)
			if err != nil {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = ent.Seq
				rep.Error = err.Error()
				return rep, nil
			}
			if ent.Seq != expectedSeq || ent.PrevHash != expectedPrev {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = expectedSeq
				rep.Error = fmt.Sprintf("chain discontinuity: expected seq=%d prev=%s, got seq=%d prev=%s", expectedSeq, expectedPrev, ent.Seq, ent.PrevHash)
				return rep, nil
			}
			calc := ComputeEntryHash(ent.Seq, ent.Timestamp, ent.Kind, ent.PrevHash, compactPayload)
			if !strings.EqualFold(calc, ent.Hash) {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = ent.Seq
				rep.Error = fmt.Sprintf("hash mismatch: expected %s, stored %s", calc, ent.Hash)
				return rep, nil
			}
			expectedSeq++
			expectedPrev = ent.Hash
			rep.EntriesChecked++
			rep.TipHash = ent.Hash

			l.applyEntryToCasesLocked(ent)
		}
		scanErr := sc.Err()
		_ = f.Close()
		if scanErr != nil {
			return VerifyReport{}, scanErr
		}
	}

	l.nextSeq = expectedSeq
	l.tipHash = expectedPrev
	_ = l.saveCasesSnapshotLocked()
	return rep, nil
}

func (l *Ledger) applyEntryToCasesLocked(ent Entry) {
	switch ent.Kind {
	case "finding":
		var f schema.Finding
		if json.Unmarshal(ent.Payload, &f) == nil && f.ID != "" {
			if _, exists := l.cases[f.ID]; !exists {
				l.cases[f.ID] = CaseRecord{
					FindingID: f.ID,
					Status:    StatusOpen,
					UpdatedAt: ent.Timestamp,
				}
			}
		}
	case "case_update":
		var upd CaseTransition
		if json.Unmarshal(ent.Payload, &upd) == nil && upd.FindingID != "" {
			rec := l.cases[upd.FindingID]
			rec.FindingID = upd.FindingID
			rec.Status = upd.Status
			if upd.Assignee != "" {
				rec.Assignee = upd.Assignee
			}
			rec.UpdatedAt = ent.Timestamp
			if upd.Note != "" {
				author := upd.Author
				if author == "" {
					author = "analyst"
				}
				rec.Notes = append(rec.Notes, CaseNote{
					Author:    author,
					Text:      upd.Note,
					Timestamp: ent.Timestamp,
				})
			}
			l.cases[upd.FindingID] = rec
		}
	}
}

// VerifyDir verifies the complete hash chain across all segment files in dir without altering state.
func VerifyDir(dir string) (VerifyReport, error) {
	cleanDir := filepath.Clean(dir)
	if _, err := os.Stat(cleanDir); err != nil {
		return VerifyReport{}, fmt.Errorf("stat ledger dir %q: %w", cleanDir, err)
	}
	l := &Ledger{
		dir:   cleanDir,
		cases: make(map[string]CaseRecord),
	}
	segments, err := listSegmentFiles(cleanDir)
	if err != nil {
		return VerifyReport{}, err
	}
	rep := VerifyReport{
		Valid:           true,
		Dir:             cleanDir,
		SegmentsChecked: len(segments),
		TipHash:         GenesisHash,
	}
	expectedSeq := uint64(1)
	expectedPrev := GenesisHash
	for _, segPath := range segments {
		f, err := os.Open(segPath)
		if err != nil {
			return VerifyReport{}, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), maxLineBytes)
		for sc.Scan() {
			rawLine := strings.TrimSpace(sc.Text())
			if rawLine == "" {
				continue
			}
			var ent Entry
			if err := json.Unmarshal([]byte(rawLine), &ent); err != nil {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = expectedSeq
				rep.Error = fmt.Sprintf("corrupt JSON at seq %d: %v", expectedSeq, err)
				return rep, nil
			}
			compactPayload, err := compactBytes(ent.Payload)
			if err != nil {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = ent.Seq
				rep.Error = err.Error()
				return rep, nil
			}
			if ent.Seq != expectedSeq || ent.PrevHash != expectedPrev {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = expectedSeq
				rep.Error = fmt.Sprintf("chain mismatch: expected seq=%d prev=%s, got seq=%d prev=%s", expectedSeq, expectedPrev, ent.Seq, ent.PrevHash)
				return rep, nil
			}
			calc := ComputeEntryHash(ent.Seq, ent.Timestamp, ent.Kind, ent.PrevHash, compactPayload)
			if !strings.EqualFold(calc, ent.Hash) {
				_ = f.Close()
				rep.Valid = false
				rep.BrokenSegment = filepath.Base(segPath)
				rep.BrokenAtSeq = ent.Seq
				rep.Error = fmt.Sprintf("hash mismatch: expected %s, stored %s", calc, ent.Hash)
				return rep, nil
			}
			expectedSeq++
			expectedPrev = ent.Hash
			rep.EntriesChecked++
			rep.TipHash = ent.Hash
		}
		scanErr := sc.Err()
		_ = f.Close()
		if scanErr != nil {
			return VerifyReport{}, scanErr
		}
	}
	_ = l
	return rep, nil
}

// Verify checks the live Ledger directory on disk.
func (l *Ledger) Verify() (VerifyReport, error) {
	l.mu.Lock()
	dir := l.dir
	l.mu.Unlock()
	return VerifyDir(dir)
}

// AppendEvents appends normalized events into today's or event timestamp's hash-chained segment.
func (l *Ledger) AppendEvents(events []schema.Event) error {
	if l == nil || len(events) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	for i := range events {
		ts := events[i].Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		if err := l.appendRecordLocked("event", ts.UTC(), events[i]); err != nil {
			return err
		}
	}
	return nil
}

// AppendFindings appends emitted SIEM findings into the hash chain and initializes open case states.
func (l *Ledger) AppendFindings(findings []schema.Finding) error {
	if l == nil || len(findings) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	for i := range findings {
		ts := findings[i].Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		if err := l.appendRecordLocked("finding", ts.UTC(), findings[i]); err != nil {
			return err
		}
		if findings[i].ID != "" {
			if _, exists := l.cases[findings[i].ID]; !exists {
				l.cases[findings[i].ID] = CaseRecord{
					FindingID: findings[i].ID,
					Status:    StatusOpen,
					UpdatedAt: ts.UTC().Format(time.RFC3339Nano),
				}
			}
		}
	}
	return l.saveCasesSnapshotLocked()
}

// UpdateCase transitions an incident's triage status and appends an immutable case_update entry.
func (l *Ledger) UpdateCase(findingID, rawStatus, assignee, author, note string) (CaseRecord, error) {
	if l == nil {
		return CaseRecord{}, errors.New("ledger is not enabled")
	}
	fid := strings.TrimSpace(findingID)
	if fid == "" {
		return CaseRecord{}, errors.New("finding_id is required")
	}
	status, err := ParseCaseStatus(rawStatus)
	if err != nil {
		return CaseRecord{}, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC()
	tsStr := ts.Format(time.RFC3339Nano)
	upd := CaseTransition{
		FindingID: fid,
		Status:    status,
		Assignee:  strings.TrimSpace(assignee),
		Author:    strings.TrimSpace(author),
		Note:      strings.TrimSpace(note),
	}
	if err := l.appendRecordLocked("case_update", ts, upd); err != nil {
		return CaseRecord{}, err
	}

	rec := l.cases[fid]
	rec.FindingID = fid
	rec.Status = status
	if upd.Assignee != "" {
		rec.Assignee = upd.Assignee
	}
	rec.UpdatedAt = tsStr
	if upd.Note != "" {
		a := upd.Author
		if a == "" {
			a = "analyst"
		}
		rec.Notes = append(rec.Notes, CaseNote{
			Author:    a,
			Text:      upd.Note,
			Timestamp: tsStr,
		})
	}
	l.cases[fid] = rec
	if err := l.saveCasesSnapshotLocked(); err != nil {
		return rec, err
	}
	return rec, nil
}

// ListCases returns tracked cases sorted by FindingID, optionally filtered by status.
func (l *Ledger) ListCases(statusFilter string) []CaseRecord {
	if l == nil {
		return nil
	}
	var wantStatus string
	if strings.TrimSpace(statusFilter) != "" {
		if parsed, err := ParseCaseStatus(statusFilter); err == nil {
			wantStatus = parsed
		} else {
			return nil
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var out []CaseRecord
	for _, rec := range l.cases {
		if wantStatus != "" && rec.Status != wantStatus {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FindingID < out[j].FindingID
	})
	return out
}

// GetCase retrieves one tracked case record cleanly.
func (l *Ledger) GetCase(findingID string) (CaseRecord, bool) {
	if l == nil {
		return CaseRecord{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.cases[findingID]
	return rec, ok
}

// Stats returns entry count, chain tip hash, and per-status case counts.
func (l *Ledger) Stats() (entries uint64, tipHash string, caseCounts map[string]int) {
	caseCounts = map[string]int{
		StatusOpen:          0,
		StatusAck:           0,
		StatusResolved:      0,
		StatusFalsePositive: 0,
	}
	if l == nil {
		return 0, GenesisHash, caseCounts
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entries = l.nextSeq - 1
	tipHash = l.tipHash
	for _, rec := range l.cases {
		caseCounts[rec.Status]++
	}
	return entries, tipHash, caseCounts
}

// Search queries date-partitioned ledger segments filtered by time window, entity, severity, and substring.
func (l *Ledger) Search(q SearchQuery) (SearchResult, error) {
	if l == nil {
		return SearchResult{}, errors.New("ledger is not enabled")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	var minSev schema.Severity
	if strings.TrimSpace(q.Severity) != "" {
		parsed, err := schema.ParseSeverity(q.Severity)
		if err != nil {
			return SearchResult{}, err
		}
		minSev = parsed
	}

	segments, err := listSegmentFiles(l.dir)
	if err != nil {
		return SearchResult{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(q.Query))
	kindFilter := strings.ToLower(strings.TrimSpace(q.Kind))
	switch kindFilter {
	case "events":
		kindFilter = "event"
	case "findings":
		kindFilter = "finding"
	case "cases":
		kindFilter = "case"
	}

	var res SearchResult
	for _, segPath := range segments {
		if segDate, ok := parseSegmentDate(filepath.Base(segPath)); ok {
			if !q.From.IsZero() && segDate.Add(24*time.Hour).Before(q.From.UTC()) {
				continue
			}
			if !q.To.IsZero() && segDate.After(q.To.UTC()) {
				continue
			}
		}

		f, err := os.Open(segPath)
		if err != nil {
			return res, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), maxLineBytes)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var ent Entry
			if json.Unmarshal([]byte(line), &ent) != nil {
				continue
			}
			ts, _ := time.Parse(time.RFC3339Nano, ent.Timestamp)
			if !q.From.IsZero() && ts.Before(q.From) {
				continue
			}
			if !q.To.IsZero() && ts.After(q.To) {
				continue
			}
			if kindFilter != "" && ent.Kind != kindFilter {
				continue
			}
			if needle != "" && !strings.Contains(strings.ToLower(string(ent.Payload)), needle) {
				continue
			}

			switch ent.Kind {
			case "event":
				var ev schema.Event
				if json.Unmarshal(ent.Payload, &ev) != nil {
					continue
				}
				if minSev != "" && !ev.Severity.MeetsThreshold(minSev) {
					continue
				}
				if q.RuleID != "" && !strings.EqualFold(ev.RuleID, q.RuleID) {
					continue
				}
				if q.Layer != "" && !strings.EqualFold(ev.Layer, q.Layer) {
					continue
				}
				if q.Host != "" && !strings.EqualFold(ev.Host, q.Host) {
					continue
				}
				if q.SrcIP != "" && ev.SrcIP != q.SrcIP {
					continue
				}
				if q.User != "" && !strings.EqualFold(ev.User, q.User) {
					continue
				}
				res.Events = append(res.Events, ev)
				res.Total++

			case "finding":
				var fn schema.Finding
				if json.Unmarshal(ent.Payload, &fn) != nil {
					continue
				}
				if minSev != "" && !fn.Severity.MeetsThreshold(minSev) {
					continue
				}
				if q.RuleID != "" && !strings.EqualFold(fn.RuleID, q.RuleID) {
					continue
				}
				if q.Host != "" && !strings.Contains(strings.ToLower(fn.Target), strings.ToLower(q.Host)) && !evidenceEquals(fn, "host", q.Host) {
					continue
				}
				if q.SrcIP != "" && !strings.Contains(fn.Target, q.SrcIP) && !evidenceEquals(fn, "src_ip", q.SrcIP) {
					continue
				}
				res.Findings = append(res.Findings, fn)
				res.Total++
			}
			if res.Total >= limit {
				_ = f.Close()
				return res, nil
			}
		}
		_ = f.Close()
	}
	return res, nil
}

func (l *Ledger) appendRecordLocked(kind string, ts time.Time, payload any) error {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	compactPayload, err := compactBytes(rawPayload)
	if err != nil {
		return err
	}
	tsStr := ts.UTC().Format(time.RFC3339Nano)
	hash := ComputeEntryHash(l.nextSeq, tsStr, kind, l.tipHash, compactPayload)
	ent := Entry{
		Seq:       l.nextSeq,
		Timestamp: tsStr,
		Kind:      kind,
		PrevHash:  l.tipHash,
		Hash:      hash,
		Payload:   compactPayload,
	}
	line, err := json.Marshal(ent)
	if err != nil {
		return err
	}

	segName := fmt.Sprintf("siem-%s.ndjson", ts.UTC().Format("2006-01-02"))
	segPath := filepath.Join(l.dir, segName)
	f, err := os.OpenFile(segPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open ledger segment %q: %w", segPath, err)
	}
	if _, wErr := f.Write(append(line, '\n')); wErr != nil {
		_ = f.Close()
		return wErr
	}
	_ = f.Close()

	l.nextSeq++
	l.tipHash = hash
	return nil
}

func (l *Ledger) saveCasesSnapshotLocked() error {
	outPath := filepath.Join(l.dir, "cases.json")
	list := make([]CaseRecord, 0, len(l.cases))
	for _, rec := range l.cases {
		list = append(list, rec)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].FindingID < list[j].FindingID })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, append(raw, '\n'), 0o600)
}

func (l *Ledger) pruneOldSegmentsLocked(now time.Time) error {
	segments, err := listSegmentFiles(l.dir)
	if err != nil {
		return err
	}
	cutoff := now.UTC().AddDate(0, 0, -l.retentionDays)
	for _, seg := range segments {
		if dt, ok := parseSegmentDate(filepath.Base(seg)); ok && dt.Before(cutoff) {
			_ = os.Remove(seg)
		}
	}
	return nil
}

func listSegmentFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read ledger dir %q: %w", dir, err)
	}
	var segments []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "siem-") && strings.HasSuffix(name, ".ndjson") {
			segments = append(segments, filepath.Join(dir, name))
		}
	}
	sort.Strings(segments)
	return segments, nil
}

func parseSegmentDate(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, "siem-") || !strings.HasSuffix(name, ".ndjson") {
		return time.Time{}, false
	}
	dateStr := strings.TrimSuffix(strings.TrimPrefix(name, "siem-"), ".ndjson")
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func compactBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, fmt.Errorf("compact payload JSON: %w", err)
	}
	return buf.Bytes(), nil
}

func evidenceEquals(f schema.Finding, key, wanted string) bool {
	if f.Evidence == nil {
		return false
	}
	val, ok := f.Evidence[key]
	if !ok {
		return false
	}
	return strings.EqualFold(fmt.Sprint(val), wanted)
}
