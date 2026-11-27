package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

func TestServerFailClosedAuthAndIngestLifecycle(t *testing.T) {
	// Missing API key env var must fail closed
	if _, err := New(Config{APIKeyEnv: "UNSET_SIEM_API_KEY_TEST", Policy: policy.DefaultPolicy()}); err == nil {
		t.Fatal("expected New to fail closed when APIKeyEnv is unset")
	}

	envName := "TEST_SIEM_SERVER_KEY"
	t.Setenv(envName, "local-test-api-val")

	storePath := filepath.Join(t.TempDir(), "siem-store.ndjson")
	pol := policy.DefaultPolicy()
	pol.AuthBurstThreshold = 3

	srv, err := New(Config{
		Policy:       pol,
		StorePath:    storePath,
		APIKeyEnv:    envName,
		DryRunAlerts: true,
	})
	if err != nil {
		t.Fatalf("New server failed: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Unauthenticated ingest rejected
	unauthResp, err := http.Post(ts.URL+"/api/v1/ingest", "application/json", strings.NewReader(`{"raw":"test"}`))
	if err != nil {
		t.Fatalf("unauth POST failed: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without API key, got %d", unauthResp.StatusCode)
	}

	// Healthz stays readable
	hzResp, err := http.Get(ts.URL + "/healthz")
	if err != nil || hzResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /healthz, err=%v resp=%+v", err, hzResp)
	}
	_ = hzResp.Body.Close()

	// Ingest synthetic auth brute-force lines with X-API-Key
	payload := map[string]any{
		"format": "auth",
		"lines": []string{
			"Nov 27 10:00:01 bastion-01 sshd[10]: Failed password for ops from 198.51.100.70 port 4100 ssh2",
			"Nov 27 10:00:02 bastion-01 sshd[11]: Failed password for ops from 198.51.100.70 port 4101 ssh2",
			"Nov 27 10:00:03 bastion-01 sshd[12]: Failed password for ops from 198.51.100.70 port 4102 ssh2",
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "local-test-api-val")
	inResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authenticated ingest failed: %v", err)
	}
	defer inResp.Body.Close()
	if inResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 ingest, got %d", inResp.StatusCode)
	}
	var inOut struct {
		Ingested int              `json:"ingested"`
		Emitted  int              `json:"emitted"`
		Findings []schema.Finding `json:"findings"`
	}
	if err := json.NewDecoder(inResp.Body).Decode(&inOut); err != nil {
		t.Fatalf("decode ingest resp: %v", err)
	}
	if inOut.Ingested != 3 || inOut.Emitted == 0 || inOut.Findings[0].RuleID != "SIEM-001" {
		t.Fatalf("unexpected ingest outcome: %+v", inOut)
	}

	// Query incidents with Bearer token & severity filter
	incReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/incidents?severity=medium", nil)
	incReq.Header.Set("Authorization", "Bearer local-test-api-val")
	incResp, err := http.DefaultClient.Do(incReq)
	if err != nil {
		t.Fatalf("GET incidents failed: %v", err)
	}
	defer incResp.Body.Close()
	var incOut struct {
		Total    int              `json:"total"`
		Findings []schema.Finding `json:"findings"`
	}
	if err := json.NewDecoder(incResp.Body).Decode(&incOut); err != nil || incOut.Total == 0 {
		t.Fatalf("expected incidents after ingest, total=%d err=%v", incOut.Total, err)
	}

	// Reload new Server from StorePath and verify persistence
	reloaded, err := New(Config{
		Policy:    pol,
		StorePath: storePath,
		APIKeyEnv: envName,
	})
	if err != nil {
		t.Fatalf("reload New failed: %v", err)
	}
	ts2 := httptest.NewServer(reloaded.Handler())
	defer ts2.Close()

	posReq, _ := http.NewRequest(http.MethodGet, ts2.URL+"/api/v1/posture", nil)
	posReq.Header.Set("X-API-Key", "local-test-api-val")
	posResp, err := http.DefaultClient.Do(posReq)
	if err != nil {
		t.Fatalf("GET posture on reloaded server failed: %v", err)
	}
	defer posResp.Body.Close()
	var rep schema.Report
	if err := json.NewDecoder(posResp.Body).Decode(&rep); err != nil || len(rep.Findings) == 0 {
		t.Fatalf("expected persisted findings on reload, len=%d err=%v", len(rep.Findings), err)
	}
}
