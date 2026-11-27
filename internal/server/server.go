package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-siem/internal/correlator"
	"github.com/luminariadev/raksa-siem/internal/normalizer"
	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/router"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

const maxIngestBodyBytes = 2 << 20 // 2 MiB

// Config configures the HTTP SIEM ingestion and incident query server.
type Config struct {
	Addr         string
	Policy       policy.Policy
	StorePath    string
	APIKeyEnv    string
	MaxEvents    int
	MaxIncidents int
	DryRunAlerts bool
}

type storeRecord struct {
	Kind    string          `json:"kind"`
	Event   *schema.Event   `json:"event,omitempty"`
	Finding *schema.Finding `json:"finding,omitempty"`
}

// Server exposes authenticated REST endpoints for ingesting events, querying incidents,
// posture scoring, chronological timelines, health checks, and Prometheus metrics.
type Server struct {
	cfg        Config
	pol        policy.Policy
	apiKey     string
	mu         sync.Mutex
	engine     *correlator.Engine
	router     *router.Router
	events     []schema.Event
	incidents  []schema.Finding
	suppressed int
}

// New initializes a Server, failing closed if APIKeyEnv is named but unset.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = "127.0.0.1:8484"
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 50000
	}
	if cfg.MaxIncidents <= 0 {
		cfg.MaxIncidents = 10000
	}
	pol := cfg.Policy
	if err := pol.ValidateAndCompile(); err != nil {
		return nil, err
	}
	var apiKey string
	if strings.TrimSpace(cfg.APIKeyEnv) != "" {
		apiKey = os.Getenv(strings.TrimSpace(cfg.APIKeyEnv))
		if apiKey == "" {
			return nil, fmt.Errorf("API key environment variable %q is empty or unset (fail-closed)", cfg.APIKeyEnv)
		}
	}

	s := &Server{
		cfg:    cfg,
		pol:    pol,
		apiKey: apiKey,
		engine: correlator.NewEngine(pol),
		router: router.NewRouter(pol, cfg.DryRunAlerts),
	}
	if strings.TrimSpace(cfg.StorePath) != "" {
		if err := s.loadStore(cfg.StorePath); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Handler returns the configured HTTP handler with all SIEM endpoints registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/ingest", s.withAuth(s.handleIngest))
	mux.HandleFunc("/api/v1/incidents", s.withAuth(s.handleIncidents))
	mux.HandleFunc("/api/v1/posture", s.withAuth(s.handlePosture))
	mux.HandleFunc("/api/v1/timeline", s.withAuth(s.handleTimeline))
	return mux
}

// ListenAndServe runs the HTTP server with bounded timeouts until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	httpSrv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			presented := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if presented == "" {
				authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
				if len(authHdr) > 7 && strings.EqualFold(authHdr[:7], "Bearer ") {
					presented = strings.TrimSpace(authHdr[7:])
				}
			}
			if !constantTimeEqual(presented, s.apiKey) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "unauthorized: valid X-API-Key or Authorization Bearer token required",
				})
				return
			}
		}
		next(w, r)
	}
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"tool":    schema.ToolName,
		"version": schema.Version,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.mu.Lock()
	evCount := len(s.events)
	incCopy := make([]schema.Finding, len(s.incidents))
	copy(incCopy, s.incidents)
	supCount := s.suppressed
	s.mu.Unlock()

	rep := schema.NewReport(incCopy)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP raksa_siem_ingested_events_total Buffered events currently indexed.\n")
	fmt.Fprintf(&b, "# TYPE raksa_siem_ingested_events_total gauge\n")
	fmt.Fprintf(&b, "raksa_siem_ingested_events_total %d\n", evCount)
	fmt.Fprintf(&b, "# HELP raksa_siem_incidents_total Total correlated SIEM incidents retained.\n")
	fmt.Fprintf(&b, "# TYPE raksa_siem_incidents_total gauge\n")
	fmt.Fprintf(&b, "raksa_siem_incidents_total %d\n", len(incCopy))
	fmt.Fprintf(&b, "# HELP raksa_siem_suppressed_alerts_total Total alerts suppressed by policy or deduplication.\n")
	fmt.Fprintf(&b, "# TYPE raksa_siem_suppressed_alerts_total counter\n")
	fmt.Fprintf(&b, "raksa_siem_suppressed_alerts_total %d\n", supCount)
	fmt.Fprintf(&b, "# HELP raksa_siem_posture_score Current SIEM posture score (0-100).\n")
	fmt.Fprintf(&b, "# TYPE raksa_siem_posture_score gauge\n")
	fmt.Fprintf(&b, "raksa_siem_posture_score %d\n", rep.Posture.Score)
	fmt.Fprintf(&b, "# HELP raksa_siem_incidents_by_severity Retained incidents partitioned by severity.\n")
	fmt.Fprintf(&b, "# TYPE raksa_siem_incidents_by_severity gauge\n")
	fmt.Fprintf(&b, "raksa_siem_incidents_by_severity{severity=\"critical\"} %d\n", rep.Summary.Critical)
	fmt.Fprintf(&b, "raksa_siem_incidents_by_severity{severity=\"high\"} %d\n", rep.Summary.High)
	fmt.Fprintf(&b, "raksa_siem_incidents_by_severity{severity=\"medium\"} %d\n", rep.Summary.Medium)
	fmt.Fprintf(&b, "raksa_siem_incidents_by_severity{severity=\"low\"} %d\n", rep.Summary.Low)
	fmt.Fprintf(&b, "raksa_siem_incidents_by_severity{severity=\"info\"} %d\n", rep.Summary.Info)
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed; use POST"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body exceeds 2 MiB limit or failed to read"})
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty ingest payload"})
		return
	}

	rawFmt := strings.TrimSpace(r.URL.Query().Get("format"))
	if rawFmt == "" {
		rawFmt = normalizer.FormatAuto
	}
	normFmt, err := normalizer.ParseFormat(rawFmt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	events, parseErr := parseIngestPayload(body, normFmt)
	if parseErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": parseErr.Error()})
		return
	}

	var emitted []schema.Finding
	var suppressed int

	s.mu.Lock()
	for _, ev := range events {
		s.appendEventLocked(ev)
		emitted = append(emitted, s.engine.Ingest(ev)...)
	}
	filtered, polSup := policy.ApplyPolicy(emitted, s.pol)
	suppressed += polSup
	for _, f := range filtered {
		s.appendIncidentLocked(f)
	}
	s.suppressed += suppressed

	allIncidents := make([]schema.Finding, len(s.incidents))
	copy(allIncidents, s.incidents)
	s.mu.Unlock()

	if len(filtered) > 0 {
		results, _ := s.router.Deliver(r.Context(), filtered)
		for _, res := range results {
			if res.SuppressedCount > 0 {
				s.mu.Lock()
				s.suppressed += res.SuppressedCount
				s.mu.Unlock()
				suppressed += res.SuppressedCount
				break
			}
		}
	}

	if strings.TrimSpace(s.cfg.StorePath) != "" && (len(events) > 0 || len(filtered) > 0) {
		_ = s.appendStore(s.cfg.StorePath, events, filtered)
	}

	rep := schema.NewReport(allIncidents)
	writeJSON(w, http.StatusOK, map[string]any{
		"ingested":   len(events),
		"emitted":    len(filtered),
		"suppressed": suppressed,
		"findings":   filtered,
		"posture":    rep.Posture,
	})
}

func parseIngestPayload(body []byte, normFmt string) ([]schema.Event, error) {
	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("[")) {
		// Check structured envelope {"format": "...", "events": [...], "lines": [...], "raw": "..."}
		var env struct {
			Format string         `json:"format"`
			Events []schema.Event `json:"events"`
			Lines  []string       `json:"lines"`
			Raw    string         `json:"raw"`
			Tool   string         `json:"tool"`
		}
		if json.Unmarshal(trimmed, &env) == nil && env.Tool == "" && (len(env.Events) > 0 || len(env.Lines) > 0 || strings.TrimSpace(env.Raw) != "") {
			subFmt := normFmt
			if strings.TrimSpace(env.Format) != "" {
				parsed, err := normalizer.ParseFormat(env.Format)
				if err != nil {
					return nil, err
				}
				subFmt = parsed
			}
			if len(env.Events) > 0 {
				return finalizeEvents(env.Events), nil
			}
			if len(env.Lines) > 0 {
				joined := strings.Join(env.Lines, "\n")
				evs, _, err := normalizer.ParseBytes([]byte(joined), subFmt, "http-ingest")
				return evs, err
			}
			if strings.TrimSpace(env.Raw) != "" {
				evs, _, err := normalizer.ParseBytes([]byte(env.Raw), subFmt, "http-ingest")
				return evs, err
			}
		}

		// Try direct JSON array of schema.Event
		if bytes.HasPrefix(trimmed, []byte("[")) {
			var arr []schema.Event
			if json.Unmarshal(trimmed, &arr) == nil && len(arr) > 0 {
				return finalizeEvents(arr), nil
			}
		}
	}

	evs, _, err := normalizer.ParseBytes(body, normFmt, "http-ingest")
	if err != nil {
		return nil, err
	}
	return evs, nil
}

func finalizeEvents(in []schema.Event) []schema.Event {
	now := time.Now().UTC()
	out := make([]schema.Event, len(in))
	for i, ev := range in {
		if ev.Timestamp.IsZero() {
			ev.Timestamp = now
		}
		if ev.Layer == "" {
			ev.Layer = "telemetry"
		}
		if ev.Severity == "" {
			ev.Severity = schema.SeverityInfo
		}
		if ev.ID == "" {
			ev.ID = fmt.Sprintf("ingest-%d-%d", now.UnixNano(), i)
		}
		out[i] = ev
	}
	return out
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	var minSev schema.Severity
	if rawSev := strings.TrimSpace(q.Get("severity")); rawSev != "" {
		parsed, err := schema.ParseSeverity(rawSev)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		minSev = parsed
	}
	layerFilter := strings.TrimSpace(q.Get("layer"))
	ruleFilter := strings.TrimSpace(q.Get("rule_id"))
	hostFilter := strings.TrimSpace(q.Get("host"))
	srcIPFilter := strings.TrimSpace(q.Get("src_ip"))
	limit := parsePositiveLimit(q.Get("limit"), 200, 2000)

	s.mu.Lock()
	snapshot := make([]schema.Finding, len(s.incidents))
	copy(snapshot, s.incidents)
	s.mu.Unlock()

	var matched []schema.Finding
	for _, f := range snapshot {
		if minSev != "" && !f.Severity.MeetsThreshold(minSev) {
			continue
		}
		if ruleFilter != "" && !strings.EqualFold(f.RuleID, ruleFilter) {
			continue
		}
		if layerFilter != "" && !metaMatches(f, "upstream_layer", layerFilter) && !strings.Contains(strings.ToLower(f.Description), strings.ToLower(layerFilter)) {
			continue
		}
		if hostFilter != "" && !metaMatches(f, "host", hostFilter) && !strings.Contains(strings.ToLower(f.Target), strings.ToLower(hostFilter)) {
			continue
		}
		if srcIPFilter != "" && !metaMatches(f, "src_ip", srcIPFilter) && !strings.Contains(f.Target, srcIPFilter) {
			continue
		}
		matched = append(matched, f)
	}
	correlator.SortFindings(matched)
	if len(matched) > limit {
		matched = matched[:limit]
	}

	rep := schema.NewReport(matched)
	writeJSON(w, http.StatusOK, map[string]any{
		"total":    len(matched),
		"findings": matched,
		"summary":  rep.Summary,
		"posture":  rep.Posture,
	})
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s.mu.Lock()
	snapshot := make([]schema.Finding, len(s.incidents))
	copy(snapshot, s.incidents)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, schema.NewReport(snapshot))
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	filter := correlator.TimelineFilter{
		SrcIP: strings.TrimSpace(q.Get("src_ip")),
		Host:  strings.TrimSpace(q.Get("host")),
		User:  strings.TrimSpace(q.Get("user")),
		Layer: strings.TrimSpace(q.Get("layer")),
		Limit: parsePositiveLimit(q.Get("limit"), 200, 2000),
	}

	s.mu.Lock()
	evCopy := make([]schema.Event, len(s.events))
	copy(evCopy, s.events)
	s.mu.Unlock()

	tl := correlator.BuildTimeline(evCopy, filter)
	writeJSON(w, http.StatusOK, tl)
}

func (s *Server) appendEventLocked(ev schema.Event) {
	s.events = append(s.events, ev)
	if len(s.events) > s.cfg.MaxEvents {
		s.events = append([]schema.Event(nil), s.events[len(s.events)-s.cfg.MaxEvents:]...)
	}
}

func (s *Server) appendIncidentLocked(f schema.Finding) {
	s.incidents = append(s.incidents, f)
	if len(s.incidents) > s.cfg.MaxIncidents {
		s.incidents = append([]schema.Finding(nil), s.incidents[len(s.incidents)-s.cfg.MaxIncidents:]...)
	}
}

func (s *Server) loadStore(path string) error {
	clean := filepath.Clean(path)
	f, err := os.Open(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open store %q: %w", clean, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec storeRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Kind == "event" && rec.Event != nil {
			s.appendEventLocked(*rec.Event)
		} else if rec.Kind == "finding" && rec.Finding != nil {
			s.appendIncidentLocked(*rec.Finding)
		}
	}
	return scanner.Err()
}

func (s *Server) appendStore(path string, events []schema.Event, findings []schema.Finding) error {
	clean := filepath.Clean(path)
	if dir := filepath.Dir(clean); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	for i := range events {
		rec := storeRecord{Kind: "event", Event: &events[i]}
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(raw, '\n')); err != nil {
			return err
		}
	}
	for i := range findings {
		rec := storeRecord{Kind: "finding", Finding: &findings[i]}
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(raw, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func metaMatches(f schema.Finding, key, wanted string) bool {
	if f.Evidence == nil {
		return false
	}
	val, ok := f.Evidence[key]
	if !ok {
		return false
	}
	return strings.EqualFold(fmt.Sprint(val), wanted)
}

func parsePositiveLimit(raw string, def, maxVal int) int {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return def
	}
	if n > maxVal {
		return maxVal
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(payload)
}
