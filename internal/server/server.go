package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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
	"sync/atomic"
	"time"

	"github.com/luminariadev/raksa-siem/internal/correlator"
	"github.com/luminariadev/raksa-siem/internal/ledger"
	"github.com/luminariadev/raksa-siem/internal/normalizer"
	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/router"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

const maxIngestBodyBytes = 2 << 20 // 2 MiB

// Config configures the HTTP/TLS/Syslog SIEM ingestion, ledger, RBAC, and query server.
type Config struct {
	Addr            string
	SyslogUDPAddr   string
	SyslogTCPAddr   string
	OnSyslogListen  func(proto, addr string)
	Policy          policy.Policy
	PolicyPath      string
	StorePath       string
	LedgerDir       string
	RetentionDays   int
	TLSCertFile     string
	TLSKeyFile      string
	TLSClientCAFile string
	APIKeyEnv       string
	IngestKeyEnv    string
	ReadKeyEnv      string
	AdminKeyEnv     string
	MaxEvents       int
	MaxIncidents    int
	DryRunAlerts    bool
}

type storeRecord struct {
	Kind    string          `json:"kind"`
	Event   *schema.Event   `json:"event,omitempty"`
	Finding *schema.Finding `json:"finding,omitempty"`
}

// Server exposes authenticated REST endpoints for ingesting events, querying incidents,
// historical ledger search, case triage, tamper verification, posture scoring, and metrics.
type Server struct {
	cfg        Config
	pol        policy.Policy
	adminKey   string
	ingestKey  string
	readKey    string
	mu         sync.Mutex
	engine     *correlator.Engine
	router     *router.Router
	ledger     *ledger.Ledger
	events     []schema.Event
	incidents  []schema.Finding
	suppressed int
	syslogUDP  atomic.Int64
	syslogTCP  atomic.Int64
}

// New initializes a Server, failing closed if configured key env vars are unset or ledger verification fails.
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

	readEnvKey := func(envName string) (string, error) {
		name := strings.TrimSpace(envName)
		if name == "" {
			return "", nil
		}
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("API key environment variable %q is empty or unset (fail-closed)", name)
		}
		return val, nil
	}

	adminKey, err := readEnvKey(cfg.AdminKeyEnv)
	if err != nil {
		return nil, err
	}
	legacyAPIKey, err := readEnvKey(cfg.APIKeyEnv)
	if err != nil {
		return nil, err
	}
	if adminKey == "" {
		adminKey = legacyAPIKey
	}
	ingestKey, err := readEnvKey(cfg.IngestKeyEnv)
	if err != nil {
		return nil, err
	}
	readKey, err := readEnvKey(cfg.ReadKeyEnv)
	if err != nil {
		return nil, err
	}

	var ld *ledger.Ledger
	if strings.TrimSpace(cfg.LedgerDir) != "" {
		ld, err = ledger.Open(cfg.LedgerDir, cfg.RetentionDays)
		if err != nil {
			return nil, err
		}
	}

	s := &Server{
		cfg:       cfg,
		pol:       pol,
		adminKey:  adminKey,
		ingestKey: ingestKey,
		readKey:   readKey,
		engine:    correlator.NewEngine(pol),
		router:    router.NewRouter(pol, cfg.DryRunAlerts),
		ledger:    ld,
	}
	if _, tlsErr := s.BuildTLSConfig(); tlsErr != nil {
		return nil, tlsErr
	}
	if strings.TrimSpace(cfg.StorePath) != "" {
		if err := s.loadStore(cfg.StorePath); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// BuildTLSConfig constructs optional TLS 1.2+ and client mTLS config from Config certificate paths.
func (s *Server) BuildTLSConfig() (*tls.Config, error) {
	certPath := strings.TrimSpace(s.cfg.TLSCertFile)
	keyPath := strings.TrimSpace(s.cfg.TLSKeyFile)
	caPath := strings.TrimSpace(s.cfg.TLSClientCAFile)
	if certPath == "" && keyPath == "" {
		if caPath != "" {
			return nil, errors.New("tls client CA provided without tls cert/key pair")
		}
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("both tls_cert and tls_key must be provided")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if caPath != "" {
		caBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read client CA %q: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("no valid PEM certificates in client CA %q", caPath)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

// Handler returns the configured HTTP handler with all SIEM endpoints and scoped RBAC registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/ingest", s.requireScope("ingest", s.handleIngest))
	mux.HandleFunc("/api/v1/incidents", s.requireScope("read", s.handleIncidents))
	mux.HandleFunc("/api/v1/posture", s.requireScope("read", s.handlePosture))
	mux.HandleFunc("/api/v1/timeline", s.requireScope("read", s.handleTimeline))
	mux.HandleFunc("/api/v1/search", s.requireScope("read", s.handleSearch))
	mux.HandleFunc("/api/v1/ledger/verify", s.requireScope("read", s.handleLedgerVerify))
	mux.HandleFunc("/api/v1/cases", s.handleCasesDispatch)
	mux.HandleFunc("/api/v1/reload", s.requireScope("admin", s.handleReload))
	return mux
}

// ListenAndServe runs HTTP/TLS and optional Syslog UDP/TCP receivers plus SIGHUP policy reload until ctx exits.
func (s *Server) ListenAndServe(ctx context.Context) error {
	stopSyslog, err := s.StartSyslog(ctx)
	if err != nil {
		return err
	}
	defer stopSyslog()

	registerReloadSignal(ctx, func() {
		if strings.TrimSpace(s.cfg.PolicyPath) != "" {
			_ = s.ReloadPolicy(s.cfg.PolicyPath)
		}
	})

	tlsCfg, err := s.BuildTLSConfig()
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		var serveErr error
		if tlsCfg != nil {
			serveErr = httpSrv.ListenAndServeTLS("", "")
		} else {
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
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

func (s *Server) requireScope(requiredScope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authActive := s.adminKey != "" || s.ingestKey != "" || s.readKey != ""
		if !authActive {
			next(w, r)
			return
		}
		presented := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if presented == "" {
			authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
			if len(authHdr) > 7 && strings.EqualFold(authHdr[:7], "Bearer ") {
				presented = strings.TrimSpace(authHdr[7:])
			}
		}
		if presented == "" {
			drainSmallBody(r)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "unauthorized: valid X-API-Key or Authorization Bearer token required",
			})
			return
		}

		isAdmin := constantTimeEqual(presented, s.adminKey)
		isIngest := constantTimeEqual(presented, s.ingestKey)
		isRead := constantTimeEqual(presented, s.readKey)
		if !isAdmin && !isIngest && !isRead {
			drainSmallBody(r)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "unauthorized: unrecognized API token",
			})
			return
		}

		allowed := isAdmin ||
			(requiredScope == "ingest" && isIngest) ||
			(requiredScope == "read" && isRead)
		if !allowed {
			drainSmallBody(r)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("forbidden: scope %q required", requiredScope),
			})
			return
		}
		next(w, r)
	}
}

func drainSmallBody(r *http.Request) {
	if r != nil && r.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64*1024))
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
	fmt.Fprintf(&b, "# HELP raksa_siem_syslog_received_total Total syslog messages ingested over UDP or TCP.\n")
	fmt.Fprintf(&b, "# TYPE raksa_siem_syslog_received_total counter\n")
	fmt.Fprintf(&b, "raksa_siem_syslog_received_total{proto=\"udp\"} %d\n", s.syslogUDP.Load())
	fmt.Fprintf(&b, "raksa_siem_syslog_received_total{proto=\"tcp\"} %d\n", s.syslogTCP.Load())
	if s.ledger != nil {
		entries, _, counts := s.ledger.Stats()
		fmt.Fprintf(&b, "# HELP raksa_siem_ledger_entries_total Total tamper-evident hash-chained ledger entries.\n")
		fmt.Fprintf(&b, "# TYPE raksa_siem_ledger_entries_total counter\n")
		fmt.Fprintf(&b, "raksa_siem_ledger_entries_total %d\n", entries)
		fmt.Fprintf(&b, "# HELP raksa_siem_cases_by_status Tracked incident cases by triage status.\n")
		fmt.Fprintf(&b, "# TYPE raksa_siem_cases_by_status gauge\n")
		for _, st := range []string{ledger.StatusOpen, ledger.StatusAck, ledger.StatusResolved, ledger.StatusFalsePositive} {
			fmt.Fprintf(&b, "raksa_siem_cases_by_status{status=%q} %d\n", st, counts[st])
		}
	}
	_, _ = w.Write([]byte(b.String()))
}

// ReloadPolicy atomically reloads and compiles a policy file for the running server engine and router.
func (s *Server) ReloadPolicy(policyPath string) error {
	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.pol = pol
	s.cfg.PolicyPath = policyPath
	s.engine = correlator.NewEngine(pol)
	s.router = router.NewRouter(pol, s.cfg.DryRunAlerts)
	s.mu.Unlock()
	return nil
}

// IngestEvents runs normalized events through the correlator, policy, alert router, store, and hash-chained ledger.
func (s *Server) IngestEvents(ctx context.Context, events []schema.Event) ([]schema.Finding, int, *schema.PostureScore) {
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
	rt := s.router
	s.mu.Unlock()

	if len(filtered) > 0 {
		results, _ := rt.Deliver(ctx, filtered)
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
	if s.ledger != nil {
		_ = s.ledger.AppendEvents(events)
		_ = s.ledger.AppendFindings(filtered)
	}

	rep := schema.NewReport(allIncidents)
	return filtered, suppressed, rep.Posture
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

	filtered, suppressed, posture := s.IngestEvents(r.Context(), events)
	writeJSON(w, http.StatusOK, map[string]any{
		"ingested":   len(events),
		"emitted":    len(filtered),
		"suppressed": suppressed,
		"findings":   filtered,
		"posture":    posture,
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

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.ledger == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "historical search requires --ledger-dir"})
		return
	}
	q := r.URL.Query()
	var fromT, toT time.Time
	if raw := strings.TrimSpace(q.Get("from")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid 'from' timestamp (expected RFC3339)"})
			return
		}
		fromT = t
	}
	if raw := strings.TrimSpace(q.Get("to")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid 'to' timestamp (expected RFC3339)"})
			return
		}
		toT = t
	}

	res, err := s.ledger.Search(ledger.SearchQuery{
		From:     fromT,
		To:       toT,
		Kind:     strings.TrimSpace(q.Get("kind")),
		Query:    strings.TrimSpace(q.Get("query")),
		Severity: strings.TrimSpace(q.Get("severity")),
		RuleID:   strings.TrimSpace(q.Get("rule_id")),
		Layer:    strings.TrimSpace(q.Get("layer")),
		Host:     strings.TrimSpace(q.Get("host")),
		SrcIP:    strings.TrimSpace(q.Get("src_ip")),
		User:     strings.TrimSpace(q.Get("user")),
		Limit:    parsePositiveLimit(q.Get("limit"), 200, 2000),
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleLedgerVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.ledger == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ledger verification requires --ledger-dir"})
		return
	}
	rep, err := s.ledger.Verify()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	status := http.StatusOK
	if !rep.Valid {
		status = http.StatusConflict
	}
	writeJSON(w, status, rep)
}

func (s *Server) handleCasesDispatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.requireScope("read", s.handleCasesGet)(w, r)
	case http.MethodPost:
		s.requireScope("admin", s.handleCasesPost)(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed; use GET or POST"})
	}
}

func (s *Server) handleCasesGet(w http.ResponseWriter, r *http.Request) {
	if s.ledger == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "case workflow requires --ledger-dir"})
		return
	}
	cases := s.ledger.ListCases(r.URL.Query().Get("status"))
	if cases == nil {
		cases = []ledger.CaseRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": len(cases),
		"cases": cases,
	})
}

func (s *Server) handleCasesPost(w http.ResponseWriter, r *http.Request) {
	if s.ledger == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "case workflow requires --ledger-dir"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	var req struct {
		FindingID string `json:"finding_id"`
		Status    string `json:"status"`
		Assignee  string `json:"assignee"`
		Author    string `json:"author"`
		Note      string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid case update JSON: " + err.Error()})
		return
	}
	rec, err := s.ledger.UpdateCase(req.FindingID, req.Status, req.Assignee, req.Author, req.Note)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed; use POST"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var body struct {
		PolicyPath string `json:"policy_path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	target := strings.TrimSpace(body.PolicyPath)
	if target == "" {
		target = strings.TrimSpace(s.cfg.PolicyPath)
	}
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no policy_path configured or supplied"})
		return
	}
	if err := s.ReloadPolicy(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "policy_path": target})
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
