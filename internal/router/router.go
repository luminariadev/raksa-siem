package router

import (
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
	Delivered       bool   `json:"delivered"`
	DryRun          bool   `json:"dry_run,omitempty"`
	StatusCode      int    `json:"status_code,omitempty"`
	Error           string `json:"error,omitempty"`
}

// Router routes correlated SIEM findings to configured sinks with alert suppression.
type Router struct {
	Routes          []policy.AlertRoute
	Tracker         *SuppressionTracker
	HTTPClient      *http.Client
	DryRun          bool
	TelegramBaseURL string
}

// NewRouter initializes a Router from a validated Policy.
func NewRouter(pol policy.Policy, dryRun bool) *Router {
	routes := make([]policy.AlertRoute, len(pol.Routes))
	copy(routes, pol.Routes)
	return &Router{
		Routes:  routes,
		Tracker: NewSuppressionTracker(pol.SuppressionDuration()),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		DryRun:          dryRun,
		TelegramBaseURL: "https://api.telegram.org",
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
		return r.postJSON(ctx, route.URL, raw, sigHeader, res)

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
		return r.postJSON(ctx, route.URL, raw, "", res)

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
		return r.postJSON(ctx, route.URL, raw, "", res)

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
		return r.postJSON(ctx, endpoint, raw, "", res)

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

func (r *Router) postJSON(ctx context.Context, targetURL string, body []byte, signature string, res *DeliveryResult) error {
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "raksa-siem/"+schema.Version)
	if signature != "" {
		req.Header.Set("X-Raksa-Signature", signature)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", sanitizeTargetForErr(targetURL), err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	res.StatusCode = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sink returned HTTP %d", resp.StatusCode)
	}
	return nil
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
