package router

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

// ValidateSinkURL ensures alert sinks only target HTTPS endpoints or localhost/127.0.0.1 for local testing.
func ValidateSinkURL(raw string) error {
	return policy.ValidateHTTPSOrLocalhostURL(raw)
}

type suppEntry struct {
	lastSent   time.Time
	suppressed int
}

// SuppressionTracker deduplicates (rule_id, group_key) alerts inside a configured time window.
type SuppressionTracker struct {
	mu         sync.Mutex
	window     time.Duration
	entries    map[string]*suppEntry
	delivered  int
	suppressed int
	maxTracked int
}

// NewSuppressionTracker builds a tracker with the supplied cooldown duration.
func NewSuppressionTracker(window time.Duration) *SuppressionTracker {
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &SuppressionTracker{
		window:     window,
		entries:    make(map[string]*suppEntry),
		maxTracked: 8192,
	}
}

// GroupKey derives the stable deduplication key for a finding.
func GroupKey(f schema.Finding) string {
	if strings.TrimSpace(f.Target) != "" {
		return strings.TrimSpace(f.Target)
	}
	return "global"
}

// Check records a (ruleID, groupKey) occurrence and reports whether it should be emitted or suppressed.
func (st *SuppressionTracker) Check(ruleID, groupKey string, now time.Time) (deliver bool, suppressedCount int) {
	if st == nil {
		return true, 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := ruleID + "|" + groupKey
	entry, ok := st.entries[key]
	if ok && now.Sub(entry.lastSent) < st.window {
		entry.suppressed++
		st.suppressed++
		return false, entry.suppressed
	}

	if len(st.entries) >= st.maxTracked {
		st.pruneLocked(now)
	}
	if !ok {
		entry = &suppEntry{}
		st.entries[key] = entry
	}
	priorSuppressed := entry.suppressed
	entry.lastSent = now
	entry.suppressed = 0
	st.delivered++
	return true, priorSuppressed
}

// FilterBatch filters a slice of findings through the suppression window and returns both
// alerts to deliver and how many alerts were suppressed in this call.
func (st *SuppressionTracker) FilterBatch(findings []schema.Finding, now time.Time) (toDeliver []schema.Finding, suppressedInBatch int) {
	if len(findings) == 0 {
		return nil, 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for _, f := range findings {
		ok, _ := st.Check(f.RuleID, GroupKey(f), now)
		if ok {
			toDeliver = append(toDeliver, f)
		} else {
			suppressedInBatch++
		}
	}
	return toDeliver, suppressedInBatch
}

// Stats returns cumulative (delivered, suppressed) alert counts tracked so far.
func (st *SuppressionTracker) Stats() (delivered int, suppressed int) {
	if st == nil {
		return 0, 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.delivered, st.suppressed
}

func (st *SuppressionTracker) pruneLocked(now time.Time) {
	for k, e := range st.entries {
		if now.Sub(e.lastSent) >= st.window {
			delete(st.entries, k)
		}
	}
	for len(st.entries) > st.maxTracked {
		for k := range st.entries {
			delete(st.entries, k)
			break
		}
	}
}

// DeliveryResult summarizes the outcome for one alert route dispatch.
type DeliveryResult struct {
	RouteName       string `json:"route_name,omitempty"`
	RouteType       string `json:"route_type"`
	Target          string `json:"target"`
	AlertCount      int    `json:"alert_count"`
	SuppressedCount int    `json:"suppressed_count"`
	Attempts        int    `json:"attempts,omitempty"`
	Delivered       bool   `json:"delivered"`
	DLQWritten      bool   `json:"dlq_written,omitempty"`
	DryRun          bool   `json:"dry_run,omitempty"`
	StatusCode      int    `json:"status_code,omitempty"`
	Error           string `json:"error,omitempty"`
}

// DLQRecord captures a failed alert delivery batch for offline or scheduled replay.
type DLQRecord struct {
	FailedAt   string           `json:"failed_at"`
	RouteName  string           `json:"route_name,omitempty"`
	RouteType  string           `json:"route_type"`
	Target     string           `json:"target"`
	Suppressed int              `json:"suppressed"`
	Error      string           `json:"error"`
	Findings   []schema.Finding `json:"findings"`
}

// Router routes correlated SIEM findings to configured sinks with alert suppression, retry backoff, and DLQ.
type Router struct {
	Routes          []policy.AlertRoute
	Tracker         *SuppressionTracker
	HTTPClient      *http.Client
	DryRun          bool
	TelegramBaseURL string
	PagerDutyURL    string
	OpsgenieURL     string
	DLQPath         string
	MaxRetries      int
	RetryBaseDelay  time.Duration
}

// NewRouter initializes a Router from a validated Policy.
func NewRouter(pol policy.Policy, dryRun bool) *Router {
	routes := make([]policy.AlertRoute, len(pol.Routes))
	copy(routes, pol.Routes)
	maxR := pol.MaxRetries
	if maxR < 0 {
		maxR = 0
	}
	return &Router{
		Routes:  routes,
		Tracker: NewSuppressionTracker(pol.SuppressionDuration()),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		DryRun:          dryRun,
		TelegramBaseURL: "https://api.telegram.org",
		PagerDutyURL:    "https://events.pagerduty.com/v2/enqueue",
		OpsgenieURL:     "https://api.opsgenie.com/v2/alerts",
		DLQPath:         pol.DLQPath,
		MaxRetries:      maxR,
		RetryBaseDelay:  150 * time.Millisecond,
	}
}

// Deliver applies alert suppression and delivers matching findings to all configured routes.
func (r *Router) Deliver(ctx context.Context, findings []schema.Finding) ([]DeliveryResult, error) {
	if r == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	active, suppressedCount := r.Tracker.FilterBatch(findings, now)
	if len(r.Routes) == 0 {
		return nil, nil
	}

	var results []DeliveryResult
	var firstErr error
	for _, route := range r.Routes {
		matched := filterRouteSeverity(active, route.MinSeverity)
		res := DeliveryResult{
			RouteName:       route.Name,
			RouteType:       strings.ToLower(strings.TrimSpace(route.Type)),
			SuppressedCount: suppressedCount,
			AlertCount:      len(matched),
			DryRun:          r.DryRun,
		}
		if len(matched) == 0 {
			res.Target = routeTargetLabel(route)
			results = append(results, res)
			continue
		}

		err := r.dispatchRoute(ctx, route, matched, suppressedCount, &res)
		if err != nil {
			res.Error = err.Error()
			if !r.DryRun && strings.TrimSpace(r.DLQPath) != "" {
				if dlqErr := appendDLQRecord(r.DLQPath, DLQRecord{
					FailedAt:   time.Now().UTC().Format(time.RFC3339Nano),
					RouteName:  route.Name,
					RouteType:  res.RouteType,
					Target:     res.Target,
					Suppressed: suppressedCount,
					Error:      res.Error,
					Findings:   matched,
				}); dlqErr == nil {
					res.DLQWritten = true
				}
			}
			if firstErr == nil {
				firstErr = err
			}
		} else if !r.DryRun {
			res.Delivered = true
		}
		results = append(results, res)
	}
	return results, firstErr
}

func filterRouteSeverity(findings []schema.Finding, minSev schema.Severity) []schema.Finding {
	if minSev == "" {
		return findings
	}
	var out []schema.Finding
	for _, f := range findings {
		if f.Severity.MeetsThreshold(minSev) {
			out = append(out, f)
		}
	}
	return out
}

func routeTargetLabel(route policy.AlertRoute) string {
	switch strings.ToLower(strings.TrimSpace(route.Type)) {
	case "file":
		return route.Path
	case "telegram":
		return "telegram:" + route.ChatID
	default:
		return route.URL
	}
}

func (r *Router) dispatchRoute(ctx context.Context, route policy.AlertRoute, findings []schema.Finding, suppressed int, res *DeliveryResult) error {
	switch strings.ToLower(strings.TrimSpace(route.Type)) {
	case "webhook":
		res.Target = route.URL
		if err := ValidateSinkURL(route.URL); err != nil {
			return err
		}
		payload := map[string]any{
			"schema_version": schema.SchemaVersion,
			"tool":           schema.ToolName,
			"generated_at":   time.Now().UTC().Format(time.RFC3339),
			"count":          len(findings),
			"suppressed":     suppressed,
			"findings":       findings,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		var sigHeader string
		if route.SecretEnv != "" {
			secret := os.Getenv(route.SecretEnv)
			if secret == "" && !r.DryRun {
				return fmt.Errorf("HMAC secret env var %q is empty or unset", route.SecretEnv)
			}
			if secret != "" {
				mac := hmac.New(sha256.New, []byte(secret))
				_, _ = mac.Write(raw)
				sigHeader = "sha256=" + hex.EncodeToString(mac.Sum(nil))
			}
		}
		if r.DryRun {
			return nil
		}
		var headers map[string]string
		if sigHeader != "" {
			headers = map[string]string{"X-Raksa-Signature": sigHeader}
		}
		return r.postJSON(ctx, route.URL, raw, headers, res)

	case "slack":
		res.Target = route.URL
		if err := ValidateSinkURL(route.URL); err != nil {
			return err
		}
		raw, err := json.Marshal(map[string]string{
			"text": formatAlertText(findings, suppressed),
		})
		if err != nil {
			return err
		}
		if r.DryRun {
			return nil
		}
		return r.postJSON(ctx, route.URL, raw, nil, res)

	case "discord":
		res.Target = route.URL
		if err := ValidateSinkURL(route.URL); err != nil {
			return err
		}
		text := formatAlertText(findings, suppressed)
		if len(text) > 1900 {
			text = text[:1900] + "\n... (truncated)"
		}
		raw, err := json.Marshal(map[string]string{
			"content": text,
		})
		if err != nil {
			return err
		}
		if r.DryRun {
			return nil
		}
		return r.postJSON(ctx, route.URL, raw, nil, res)

	case "telegram":
		res.Target = "telegram:" + route.ChatID
		token := os.Getenv(route.TokenEnv)
		if token == "" {
			if r.DryRun {
				return nil
			}
			return fmt.Errorf("telegram bot token env var %q is empty or unset", route.TokenEnv)
		}
		base := strings.TrimRight(r.TelegramBaseURL, "/")
		if base == "" {
			base = "https://api.telegram.org"
		}
		endpoint := fmt.Sprintf("%s/bot%s/sendMessage", base, token)
		if err := ValidateSinkURL(endpoint); err != nil {
			return err
		}
		raw, err := json.Marshal(map[string]string{
			"chat_id": route.ChatID,
			"text":    formatAlertText(findings, suppressed),
		})
		if err != nil {
			return err
		}
		if r.DryRun {
			return nil
		}
		return r.postJSON(ctx, endpoint, raw, nil, res)

	case "teams":
		res.Target = route.URL
		if err := ValidateSinkURL(route.URL); err != nil {
			return err
		}
		raw, err := json.Marshal(map[string]any{
			"@type":      "MessageCard",
			"@context":   "https://schema.org/extensions",
			"summary":    fmt.Sprintf("raksa-siem detected %d incident(s)", len(findings)),
			"themeColor": "DC2626",
			"title":      fmt.Sprintf("[raksa-siem] %d Correlated Security Incident(s)", len(findings)),
			"text":       formatAlertText(findings, suppressed),
		})
		if err != nil {
			return err
		}
		if r.DryRun {
			return nil
		}
		return r.postJSON(ctx, route.URL, raw, nil, res)

	case "pagerduty":
		endpoint := strings.TrimSpace(route.URL)
		if endpoint == "" {
			endpoint = r.PagerDutyURL
		}
		if endpoint == "" {
			endpoint = "https://events.pagerduty.com/v2/enqueue"
		}
		res.Target = endpoint
		if err := ValidateSinkURL(endpoint); err != nil {
			return err
		}
		routingKey := os.Getenv(route.TokenEnv)
		if routingKey == "" {
			if r.DryRun {
				return nil
			}
			return fmt.Errorf("pagerduty routing key env var %q is empty or unset", route.TokenEnv)
		}
		top := findings[0]
		pdSev := mapPagerDutySeverity(top.Severity)
		raw, err := json.Marshal(map[string]any{
			"routing_key":  routingKey,
			"event_action": "trigger",
			"dedup_key":    top.RuleID + "|" + GroupKey(top),
			"payload": map[string]any{
				"summary":  formatAlertText(findings, suppressed),
				"source":   GroupKey(top),
				"severity": pdSev,
				"component": schema.ToolName,
				"group":    top.Module,
				"class":    top.RuleID,
			},
		})
		if err != nil {
			return err
		}
		if r.DryRun {
			return nil
		}
		return r.postJSON(ctx, endpoint, raw, nil, res)

	case "opsgenie":
		endpoint := strings.TrimSpace(route.URL)
		if endpoint == "" {
			endpoint = r.OpsgenieURL
		}
		if endpoint == "" {
			endpoint = "https://api.opsgenie.com/v2/alerts"
		}
		res.Target = endpoint
		if err := ValidateSinkURL(endpoint); err != nil {
			return err
		}
		apiKey := os.Getenv(route.TokenEnv)
		if apiKey == "" {
			if r.DryRun {
				return nil
			}
			return fmt.Errorf("opsgenie api key env var %q is empty or unset", route.TokenEnv)
		}
		top := findings[0]
		raw, err := json.Marshal(map[string]any{
			"message":     fmt.Sprintf("[%s] %s (%d incidents)", strings.ToUpper(string(top.Severity)), top.Title, len(findings)),
			"alias":       top.RuleID + "|" + GroupKey(top),
			"description": formatAlertText(findings, suppressed),
			"priority":    mapOpsgeniePriority(top.Severity),
			"source":      schema.ToolName,
			"tags":        []string{"raksa-siem", top.RuleID, top.Module},
		})
		if err != nil {
			return err
		}
		if r.DryRun {
			return nil
		}
		return r.postJSON(ctx, endpoint, raw, map[string]string{
			"Authorization": "GenieKey " + apiKey,
		}, res)

	case "file":
		cleanPath := filepath.Clean(route.Path)
		res.Target = cleanPath
		if r.DryRun {
			return nil
		}
		if dir := filepath.Dir(cleanPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("create alert sink dir %q: %w", dir, err)
			}
		}
		f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open alert file %q: %w", cleanPath, err)
		}
		defer f.Close()
		for _, item := range findings {
			line, err := json.Marshal(item)
			if err != nil {
				return err
			}
			if _, err := f.Write(append(line, '\n')); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported route type %q", route.Type)
	}
}

func (r *Router) postJSON(ctx context.Context, targetURL string, body []byte, extraHeaders map[string]string, res *DeliveryResult) error {
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	baseDelay := r.RetryBaseDelay
	if baseDelay <= 0 {
		baseDelay = 150 * time.Millisecond
	}
	totalAttempts := 1 + r.MaxRetries

	var lastErr error
	for attempt := 0; attempt < totalAttempts; attempt++ {
		res.Attempts = attempt + 1
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "raksa-siem/"+schema.Version)
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		resp, doErr := client.Do(req)
		if doErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			res.StatusCode = resp.StatusCode
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("sink returned HTTP %d", resp.StatusCode)
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return lastErr
			}
		} else {
			lastErr = fmt.Errorf("post %s: %w", sanitizeTargetForErr(targetURL), doErr)
		}

		if attempt+1 < totalAttempts {
			wait := baseDelay * time.Duration(1<<attempt)
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return lastErr
}

// ReplayDLQ attempts redelivery of failed DLQ batches stored in dlqPath and rewrites any remaining failures.
func (r *Router) ReplayDLQ(ctx context.Context, dlqPath string) (replayed int, remaining int, err error) {
	clean := filepath.Clean(dlqPath)
	raw, readErr := os.ReadFile(clean)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return 0, 0, nil
		}
		return 0, 0, readErr
	}
	var pending []DLQRecord
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec DLQRecord
		if json.Unmarshal([]byte(line), &rec) == nil && len(rec.Findings) > 0 {
			pending = append(pending, rec)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}

	var kept [][]byte
	for _, rec := range pending {
		route, ok := r.findRouteForRecord(rec)
		if !ok {
			rawLine, _ := json.Marshal(rec)
			kept = append(kept, rawLine)
			remaining++
			continue
		}
		var res DeliveryResult
		if err := r.dispatchRoute(ctx, route, rec.Findings, rec.Suppressed, &res); err != nil {
			rec.Error = err.Error()
			rawLine, _ := json.Marshal(rec)
			kept = append(kept, rawLine)
			remaining++
		} else {
			replayed++
		}
	}

	if len(kept) == 0 {
		_ = os.WriteFile(clean, []byte{}, 0o600)
		return replayed, 0, nil
	}
	var out bytes.Buffer
	for _, k := range kept {
		out.Write(k)
		out.WriteByte('\n')
	}
	if writeErr := os.WriteFile(clean, out.Bytes(), 0o600); writeErr != nil {
		return replayed, remaining, writeErr
	}
	return replayed, remaining, nil
}

func (r *Router) findRouteForRecord(rec DLQRecord) (policy.AlertRoute, bool) {
	for _, rt := range r.Routes {
		if rec.RouteName != "" && rt.Name == rec.RouteName {
			return rt, true
		}
		if strings.EqualFold(rt.Type, rec.RouteType) {
			return rt, true
		}
	}
	return policy.AlertRoute{}, false
}

func appendDLQRecord(dlqPath string, rec DLQRecord) error {
	clean := filepath.Clean(dlqPath)
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
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	return err
}

func mapPagerDutySeverity(sev schema.Severity) string {
	switch sev {
	case schema.SeverityCritical:
		return "critical"
	case schema.SeverityHigh:
		return "error"
	case schema.SeverityMedium:
		return "warning"
	default:
		return "info"
	}
}

func mapOpsgeniePriority(sev schema.Severity) string {
	switch sev {
	case schema.SeverityCritical:
		return "P1"
	case schema.SeverityHigh:
		return "P2"
	case schema.SeverityMedium:
		return "P3"
	case schema.SeverityLow:
		return "P4"
	default:
		return "P5"
	}
}

func sanitizeTargetForErr(raw string) string {
	idx := strings.Index(raw, "/bot")
	if idx > 0 {
		return raw[:idx] + "/bot<redacted>"
	}
	return raw
}

func formatAlertText(findings []schema.Finding, suppressed int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[raksa-siem] %d new incident(s)", len(findings))
	if suppressed > 0 {
		fmt.Fprintf(&b, " (%d suppressed inside window)", suppressed)
	}
	limit := len(findings)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		f := findings[i]
		fmt.Fprintf(&b, "\n- [%s] %s (%s): %s", strings.ToUpper(string(f.Severity)), f.RuleID, f.Target, f.Description)
	}
	if len(findings) > limit {
		fmt.Fprintf(&b, "\n... and %d more findings", len(findings)-limit)
	}
	return b.String()
}
