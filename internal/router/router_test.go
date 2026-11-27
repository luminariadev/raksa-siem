package router

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestValidateSinkURLAndSuppression(t *testing.T) {
	if err := ValidateSinkURL("https://hooks.example.invalid/webhook"); err != nil {
		t.Fatalf("expected HTTPS URL to pass, got %v", err)
	}
	if err := ValidateSinkURL("http://127.0.0.1:8080/hook"); err != nil {
		t.Fatalf("expected localhost HTTP URL to pass, got %v", err)
	}
	if err := ValidateSinkURL("http://remote.example.invalid/hook"); err == nil {
		t.Fatal("expected non-localhost HTTP URL to be rejected")
	}

	tracker := NewSuppressionTracker(10 * time.Minute)
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	f1 := schema.Finding{RuleID: "SIEM-001", Severity: schema.SeverityHigh, Target: "ip://198.51.100.10", Description: "first"}
	f2 := schema.Finding{RuleID: "SIEM-001", Severity: schema.SeverityHigh, Target: "ip://198.51.100.10", Description: "dup"}
	f3 := schema.Finding{RuleID: "SIEM-001", Severity: schema.SeverityHigh, Target: "ip://203.0.113.5", Description: "other target"}

	deliver, suppressed := tracker.FilterBatch([]schema.Finding{f1, f2, f3}, now)
	if len(deliver) != 2 || suppressed != 1 {
		t.Fatalf("expected 2 delivered and 1 suppressed, got len=%d suppressed=%d", len(deliver), suppressed)
	}

	deliverAfter, _ := tracker.FilterBatch([]schema.Finding{f1}, now.Add(11*time.Minute))
	if len(deliverAfter) != 1 {
		t.Fatalf("expected cooldown expiry after 11m to re-deliver finding, got %d", len(deliverAfter))
	}
}

func TestRouterDeliveryWebhookHMACSlackDiscordTelegramAndFile(t *testing.T) {
	var gotWebhookSig string
	var gotWebhookBody []byte
	var gotSlackText string
	var gotDiscordContent string
	var gotTelegramChat string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/webhook":
			gotWebhookSig = r.Header.Get("X-Raksa-Signature")
			gotWebhookBody = raw
		case "/slack":
			var p map[string]string
			_ = json.Unmarshal(raw, &p)
			gotSlackText = p["text"]
		case "/discord":
			var p map[string]string
			_ = json.Unmarshal(raw, &p)
			gotDiscordContent = p["content"]
		case "/botsynthetic-tg-val/sendMessage":
			var p map[string]string
			_ = json.Unmarshal(raw, &p)
			gotTelegramChat = p["chat_id"]
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hmacEnv := "TEST_SIEM_HMAC_SIG_KEY"
	tgEnv := "TEST_SIEM_TG_BOT_KEY"
	t.Setenv(hmacEnv, "local-test-hmac-value")
	t.Setenv(tgEnv, "synthetic-tg-val")

	sinkFile := filepath.Join(t.TempDir(), "alerts.ndjson")
	pol := policy.DefaultPolicy()
	pol.Routes = []policy.AlertRoute{
		{Name: "wh", Type: "webhook", URL: srv.URL + "/webhook", SecretEnv: hmacEnv, MinSeverity: schema.SeverityMedium},
		{Name: "sl", Type: "slack", URL: srv.URL + "/slack", MinSeverity: schema.SeverityHigh},
		{Name: "dc", Type: "discord", URL: srv.URL + "/discord", MinSeverity: schema.SeverityHigh},
		{Name: "tg", Type: "telegram", TokenEnv: tgEnv, ChatID: "-100123", MinSeverity: schema.SeverityHigh},
		{Name: "fl", Type: "file", Path: sinkFile, MinSeverity: schema.SeverityMedium},
	}

	rt := NewRouter(pol, false)
	rt.TelegramBaseURL = srv.URL

	findings := []schema.Finding{
		{RuleID: "SIEM-201", Severity: schema.SeverityHigh, Target: "ip://198.51.100.10", Description: "cross-layer IP correlation"},
		{RuleID: "SIEM-201", Severity: schema.SeverityHigh, Target: "ip://198.51.100.10", Description: "suppressed duplicate"},
	}

	results, err := rt.Deliver(context.Background(), findings)
	if err != nil {
		t.Fatalf("Deliver failed: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("expected 5 route results, got %d", len(results))
	}
	for _, res := range results {
		if !res.Delivered || res.AlertCount != 1 || res.SuppressedCount != 1 {
			t.Fatalf("unexpected delivery result %+v", res)
		}
	}

	mac := hmac.New(sha256.New, []byte("local-test-hmac-value"))
	_, _ = mac.Write(gotWebhookBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotWebhookSig != expectedSig {
		t.Fatalf("HMAC mismatch: got %q want %q", gotWebhookSig, expectedSig)
	}
	if !strings.Contains(gotSlackText, "SIEM-201") || !strings.Contains(gotDiscordContent, "SIEM-201") || gotTelegramChat != "-100123" {
		t.Fatalf("sink payloads incomplete: slack=%q discord=%q tg=%q", gotSlackText, gotDiscordContent, gotTelegramChat)
	}

	fileBytes, err := os.ReadFile(sinkFile)
	if err != nil || !strings.Contains(string(fileBytes), "SIEM-201") {
		t.Fatalf("expected alert written to %s: err=%v body=%s", sinkFile, err, string(fileBytes))
	}

	// Verify DryRun produces no file writes or HTTP requests on new target
	dryFile := filepath.Join(t.TempDir(), "dry.ndjson")
	polDry := policy.DefaultPolicy()
	polDry.Routes = []policy.AlertRoute{{Name: "dry", Type: "file", Path: dryFile}}
	dryRouter := NewRouter(polDry, true)
	dryRes, err := dryRouter.Deliver(context.Background(), []schema.Finding{{RuleID: "SIEM-001", Severity: schema.SeverityHigh, Target: "ip://203.0.113.1"}})
	if err != nil || len(dryRes) != 1 || !dryRes[0].DryRun || dryRes[0].Delivered {
		t.Fatalf("unexpected dry-run result: %+v err=%v", dryRes, err)
	}
	if _, statErr := os.Stat(dryFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected dry-run not to create %s", dryFile)
	}
}

func TestRouterRetryBackoffDLQReplayAndEnterpriseSinks(t *testing.T) {
	var flakyCalls atomic.Int32
	var dlqFailMode atomic.Bool
	dlqFailMode.Store(true)

	var gotTeams bool
	var gotPagerDutyKey string
	var gotOpsgenieAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/flaky":
			if flakyCalls.Add(1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/dlq-target":
			if dlqFailMode.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/teams":
			gotTeams = strings.Contains(string(raw), "MessageCard")
			w.WriteHeader(http.StatusOK)
		case "/pagerduty":
			var p map[string]any
			_ = json.Unmarshal(raw, &p)
			gotPagerDutyKey = p["routing_key"].(string)
			w.WriteHeader(http.StatusAccepted)
		case "/opsgenie":
			gotOpsgenieAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	pdEnv := "TEST_SIEM_PD_KEY"
	ogEnv := "TEST_SIEM_OG_KEY"
	t.Setenv(pdEnv, "pd-local-val")
	t.Setenv(ogEnv, "og-local-val")

	// 1. Transient 503 recovery on attempt 3 + Teams/PagerDuty/Opsgenie
	pol := policy.DefaultPolicy()
	pol.MaxRetries = 2
	pol.Routes = []policy.AlertRoute{
		{Name: "flaky", Type: "webhook", URL: srv.URL + "/flaky", MinSeverity: schema.SeverityHigh},
		{Name: "tm", Type: "teams", URL: srv.URL + "/teams", MinSeverity: schema.SeverityHigh},
		{Name: "pd", Type: "pagerduty", URL: srv.URL + "/pagerduty", TokenEnv: pdEnv, MinSeverity: schema.SeverityHigh},
		{Name: "og", Type: "opsgenie", URL: srv.URL + "/opsgenie", TokenEnv: ogEnv, MinSeverity: schema.SeverityHigh},
	}
	rt := NewRouter(pol, false)
	rt.RetryBaseDelay = 5 * time.Millisecond

	res, err := rt.Deliver(context.Background(), []schema.Finding{{RuleID: "SIEM-001", Severity: schema.SeverityHigh, Title: "Brute force", Target: "ip://198.51.100.10"}})
	if err != nil {
		t.Fatalf("expected retry recovery + enterprise sinks to succeed, got err=%v res=%+v", err, res)
	}
	if res[0].Attempts != 3 || !res[0].Delivered {
		t.Fatalf("expected attempt=3 recovery on flaky route, got %+v", res[0])
	}
	if !gotTeams || gotPagerDutyKey != "pd-local-val" || gotOpsgenieAuth != "GenieKey og-local-val" {
		t.Fatalf("enterprise sink assertions failed: teams=%v pd=%q og=%q", gotTeams, gotPagerDutyKey, gotOpsgenieAuth)
	}

	// 2. Permanent 500 -> DLQ write -> heal endpoint -> ReplayDLQ clears DLQ
	dlqFile := filepath.Join(t.TempDir(), "alerts-dlq.ndjson")
	polDLQ := policy.DefaultPolicy()
	polDLQ.MaxRetries = 1
	polDLQ.DLQPath = dlqFile
	polDLQ.Routes = []policy.AlertRoute{{Name: "dead", Type: "webhook", URL: srv.URL + "/dlq-target", MinSeverity: schema.SeverityHigh}}
	dlqRouter := NewRouter(polDLQ, false)
	dlqRouter.RetryBaseDelay = 5 * time.Millisecond

	dlqRes, dErr := dlqRouter.Deliver(context.Background(), []schema.Finding{{RuleID: "SIEM-201", Severity: schema.SeverityCritical, Target: "ip://203.0.113.44"}})
	if dErr == nil || len(dlqRes) != 1 || !dlqRes[0].DLQWritten {
		t.Fatalf("expected DLQ record written on persistent failure, got err=%v res=%+v", dErr, dlqRes)
	}

	dlqFailMode.Store(false)
	replayed, remaining, repErr := dlqRouter.ReplayDLQ(context.Background(), dlqFile)
	if repErr != nil || replayed != 1 || remaining != 0 {
		t.Fatalf("expected ReplayDLQ replayed=1 remaining=0, got replayed=%d remaining=%d err=%v", replayed, remaining, repErr)
	}
}
