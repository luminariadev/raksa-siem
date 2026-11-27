package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/ledger"
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

func TestServerRBACLedgerCaseReloadAndMTLS(t *testing.T) {
	ingestEnv := "TEST_SIEM_INGEST_KEY"
	readEnv := "TEST_SIEM_READ_KEY"
	adminEnv := "TEST_SIEM_ADMIN_KEY"
	t.Setenv(ingestEnv, "ingest-secret-token")
	t.Setenv(readEnv, "read-secret-token")
	t.Setenv(adminEnv, "admin-secret-token")

	tmpDir := t.TempDir()
	ledgerDir := filepath.Join(tmpDir, "ledger")
	policyPath := filepath.Join(tmpDir, "siem-policy.yaml")
	initialPolicy := `min_severity: low
auth_burst_threshold: 3
watched_ips:
  - 203.0.113.55
`
	if err := os.WriteFile(policyPath, []byte(initialPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	srv, err := New(Config{
		Policy:       pol,
		PolicyPath:   policyPath,
		LedgerDir:    ledgerDir,
		IngestKeyEnv: ingestEnv,
		ReadKeyEnv:   readEnv,
		AdminKeyEnv:  adminEnv,
		DryRunAlerts: true,
	})
	if err != nil {
		t.Fatalf("New RBAC server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, key string, body []byte) *http.Response {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, rErr := http.NewRequest(method, ts.URL+path, rdr)
		if rErr != nil {
			t.Fatal(rErr)
		}
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, dErr := http.DefaultClient.Do(req)
		if dErr != nil {
			t.Fatal(dErr)
		}
		return resp
	}

	ingestPayload := []byte(`{"format":"auth","lines":[
		"Nov 27 11:00:01 edge-01 sshd[101]: Failed password for root from 203.0.113.55 port 5001 ssh2",
		"Nov 27 11:00:02 edge-01 sshd[102]: Failed password for root from 203.0.113.55 port 5002 ssh2",
		"Nov 27 11:00:03 edge-01 sshd[103]: Failed password for root from 203.0.113.55 port 5003 ssh2"
	]}`)

	// 1. Scoped RBAC enforcement
	resp := doReq(http.MethodPost, "/api/v1/ingest", "read-secret-token", ingestPayload)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for read key on ingest, got %d", resp.StatusCode)
	}

	resp = doReq(http.MethodGet, "/api/v1/incidents", "ingest-secret-token", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for ingest key on incidents, got %d", resp.StatusCode)
	}

	resp = doReq(http.MethodPost, "/api/v1/reload", "ingest-secret-token", []byte(`{}`))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for ingest key on reload, got %d", resp.StatusCode)
	}

	// 2. Authorized ingest with ingest token
	resp = doReq(http.MethodPost, "/api/v1/ingest", "ingest-secret-token", ingestPayload)
	rawIngest, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on ingest, got %d body=%s", resp.StatusCode, string(rawIngest))
	}
	var ingestOut struct {
		Emitted  int              `json:"emitted"`
		Findings []schema.Finding `json:"findings"`
	}
	if err := json.Unmarshal(rawIngest, &ingestOut); err != nil {
		t.Fatalf("decode ingest output: %v", err)
	}
	if ingestOut.Emitted == 0 || len(ingestOut.Findings) == 0 {
		t.Fatalf("expected findings emitted, got %+v", ingestOut)
	}
	targetFindingID := ingestOut.Findings[0].ID

	// 3. Historical search, ledger verification, and RBAC read vs admin checks on /api/v1/cases
	resp = doReq(http.MethodGet, "/api/v1/search?kind=events&src_ip=203.0.113.55", "read-secret-token", nil)
	rawSearch, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on search, got %d body=%s", resp.StatusCode, string(rawSearch))
	}
	var searchRes ledger.SearchResult
	if err := json.Unmarshal(rawSearch, &searchRes); err != nil {
		t.Fatalf("decode search result: %v", err)
	}
	if searchRes.Total != 3 || len(searchRes.Events) != 3 {
		t.Fatalf("expected 3 events in search result, got total=%d len=%d", searchRes.Total, len(searchRes.Events))
	}

	resp = doReq(http.MethodGet, "/api/v1/ledger/verify", "read-secret-token", nil)
	rawVerify, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on ledger verify, got %d body=%s", resp.StatusCode, string(rawVerify))
	}
	var verifyRep ledger.VerifyReport
	if err := json.Unmarshal(rawVerify, &verifyRep); err != nil {
		t.Fatalf("decode verify report: %v", err)
	}
	if !verifyRep.Valid || verifyRep.EntriesChecked == 0 {
		t.Fatalf("expected valid non-empty ledger verify report, got %+v", verifyRep)
	}

	caseUpdate := []byte(fmt.Sprintf(`{"finding_id":%q,"status":"ack","assignee":"tier1-soc","author":"analyst","note":"triaging ssh burst"}`, targetFindingID))
	resp = doReq(http.MethodPost, "/api/v1/cases", "read-secret-token", caseUpdate)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for read key on POST /api/v1/cases, got %d", resp.StatusCode)
	}

	resp = doReq(http.MethodPost, "/api/v1/cases", "admin-secret-token", caseUpdate)
	rawCase, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin key on POST /api/v1/cases, got %d body=%s", resp.StatusCode, string(rawCase))
	}
	var updatedRec ledger.CaseRecord
	if err := json.Unmarshal(rawCase, &updatedRec); err != nil {
		t.Fatalf("decode updated case: %v", err)
	}
	if updatedRec.Status != ledger.StatusAck || updatedRec.Assignee != "tier1-soc" || len(updatedRec.Notes) != 1 {
		t.Fatalf("unexpected case record: %+v", updatedRec)
	}

	resp = doReq(http.MethodGet, "/api/v1/cases?status=ack", "read-secret-token", nil)
	rawCases, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for GET /api/v1/cases, got %d body=%s", resp.StatusCode, string(rawCases))
	}
	if !strings.Contains(string(rawCases), targetFindingID) {
		t.Fatalf("expected %s in ack cases response: %s", targetFindingID, string(rawCases))
	}

	// Verify Prometheus metrics reflect ledger and case counts
	resp = doReq(http.MethodGet, "/metrics", "", nil)
	rawMetrics, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	mStr := string(rawMetrics)
	if !strings.Contains(mStr, "raksa_siem_ledger_entries_total ") || !strings.Contains(mStr, `raksa_siem_cases_by_status{status="ack"} 1`) {
		t.Fatalf("expected ledger & case metrics in output:\n%s", mStr)
	}

	// 4. Policy hot-reload via POST /api/v1/reload
	reloadedPolicy := `min_severity: critical
auth_burst_threshold: 50
`
	if err := os.WriteFile(policyPath, []byte(reloadedPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	resp = doReq(http.MethodPost, "/api/v1/reload", "admin-secret-token", []byte(`{}`))
	rawReload, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(rawReload), `"reloaded":true`) {
		t.Fatalf("expected reload success, got status=%d body=%s", resp.StatusCode, string(rawReload))
	}

	// Subsequent medium/high burst under min_severity=critical + threshold=50 emits 0 findings
	smallBurst := []byte(`{"format":"auth","lines":[
		"Nov 27 11:01:01 edge-02 sshd[201]: Failed password for admin from 203.0.113.77 port 6001 ssh2",
		"Nov 27 11:01:02 edge-02 sshd[202]: Failed password for admin from 203.0.113.77 port 6002 ssh2",
		"Nov 27 11:01:03 edge-02 sshd[203]: Failed password for admin from 203.0.113.77 port 6003 ssh2"
	]}`)
	resp = doReq(http.MethodPost, "/api/v1/ingest", "ingest-secret-token", smallBurst)
	rawSmall, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(rawSmall), `"emitted":0`) {
		t.Fatalf("expected 0 findings after policy reload, got status=%d body=%s", resp.StatusCode, string(rawSmall))
	}

	// 5. Ephemeral CA + server + client mTLS handshake verification
	tlsDir := t.TempDir()
	caKey, caCert, caPEM := generateTestCert(t, "Raksa Test CA", true, nil, nil, false, false)
	_, _, srvCertPEM, srvKeyPEM := generateSignedCert(t, "127.0.0.1", caKey, caCert, true, false)
	_, _, cliCertPEM, cliKeyPEM := generateSignedCert(t, "raksa-client", caKey, caCert, false, true)

	caFile := filepath.Join(tlsDir, "ca.pem")
	srvCertFile := filepath.Join(tlsDir, "server.crt")
	srvKeyFile := filepath.Join(tlsDir, "server.key")
	cliCertFile := filepath.Join(tlsDir, "client.crt")
	cliKeyFile := filepath.Join(tlsDir, "client.key")
	for path, data := range map[string][]byte{
		caFile:      caPEM,
		srvCertFile: srvCertPEM,
		srvKeyFile:  srvKeyPEM,
		cliCertFile: cliCertPEM,
		cliKeyFile:  cliKeyPEM,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Fail closed when CA is given without server keypair
	if _, err := New(Config{TLSClientCAFile: caFile, Policy: policy.DefaultPolicy()}); err == nil {
		t.Fatal("expected New to fail closed when TLSClientCAFile set without cert/key")
	}

	mTLSSrv, err := New(Config{
		Policy:          policy.DefaultPolicy(),
		TLSCertFile:     srvCertFile,
		TLSKeyFile:      srvKeyFile,
		TLSClientCAFile: caFile,
		ReadKeyEnv:      readEnv,
		DryRunAlerts:    true,
	})
	if err != nil {
		t.Fatalf("New mTLS server: %v", err)
	}
	tlsCfg, err := mTLSSrv.BuildTLSConfig()
	if err != nil || tlsCfg == nil {
		t.Fatalf("BuildTLSConfig: err=%v cfg=%v", err, tlsCfg)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	httpSrv := &http.Server{Handler: mTLSSrv.Handler()}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	cliPair, err := tls.LoadX509KeyPair(cliCertFile, cliKeyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair client: %v", err)
	}

	goodClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{cliPair},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
	mResp, err := goodClient.Get("https://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("valid mTLS client failed: %v", err)
	}
	_ = mResp.Body.Close()
	if mResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on mTLS /healthz, got %d", mResp.StatusCode)
	}

	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	if _, err := noCertClient.Get("https://" + ln.Addr().String() + "/healthz"); err == nil {
		t.Fatal("expected client without client cert to fail mTLS handshake")
	}
}

func generateTestCert(t *testing.T, cn string, isCA bool, signerKey *ecdsa.PrivateKey, signerCert *x509.Certificate, serverAuth, clientAuth bool) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	if serverAuth {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if clientAuth {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	parent := tmpl
	signingPriv := priv
	if signerCert != nil && signerKey != nil {
		parent = signerCert
		signingPriv = signerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, signingPriv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return priv, parsed, certPEM
}

func generateSignedCert(t *testing.T, cn string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, serverAuth, clientAuth bool) (*ecdsa.PrivateKey, *x509.Certificate, []byte, []byte) {
	t.Helper()
	priv, cert, certPEM := generateTestCert(t, cn, false, caKey, caCert, serverAuth, clientAuth)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return priv, cert, certPEM, keyPEM
}
