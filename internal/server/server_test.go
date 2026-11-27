package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestServerSyslogUDPTCPAndMetrics(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.AuthBurstThreshold = 3

	addrCh := make(chan string, 2)
	var udpAddr, tcpAddr string

	srv, err := New(Config{
		Policy:        pol,
		SyslogUDPAddr: "127.0.0.1:0",
		SyslogTCPAddr: "127.0.0.1:0",
		OnSyslogListen: func(proto, addr string) {
			addrCh <- proto + "|" + addr
		},
		DryRunAlerts: true,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopSyslog, err := srv.StartSyslog(ctx)
	if err != nil {
		t.Fatalf("StartSyslog failed: %v", err)
	}
	defer stopSyslog()

	for i := 0; i < 2; i++ {
		val := <-addrCh
		proto, a, _ := strings.Cut(val, "|")
		if proto == "udp" {
			udpAddr = a
		} else {
			tcpAddr = a
		}
	}

	// Send 2 syslog lines via UDP and 2 via TCP for 198.51.100.88 (threshold=3 triggers SIEM-001)
	uConn, err := net.Dial("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer uConn.Close()
	for i := 1; i <= 2; i++ {
		_, _ = fmt.Fprintf(uConn, "<38>Nov 27 10:10:0%d edge-01 sshd[10%d]: Failed password for root from 198.51.100.88 port 500%d ssh2\n", i, i, i)
	}

	tConn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tConn.Close()
	for i := 3; i <= 4; i++ {
		_, _ = fmt.Fprintf(tConn, "<38>Nov 27 10:10:0%d edge-01 sshd[10%d]: Failed password for root from 198.51.100.88 port 500%d ssh2\n", i, i, i)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, gErr := http.Get(ts.URL + "/api/v1/incidents?rule_id=SIEM-001")
		if gErr == nil {
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if strings.Contains(string(raw), "198.51.100.88") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for UDP+TCP syslog SIEM-001 correlation")
		}
		time.Sleep(25 * time.Millisecond)
	}

	mResp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mBody, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()
	if !strings.Contains(string(mBody), `raksa_siem_syslog_received_total{proto="udp"} 2`) ||
		!strings.Contains(string(mBody), `raksa_siem_syslog_received_total{proto="tcp"} 2`) {
		t.Fatalf("unexpected syslog metrics output:\n%s", string(mBody))
	}
}
