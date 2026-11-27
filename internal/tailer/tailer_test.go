package tailer

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/report"
)

func TestRunWatchDetectsAppendRotationAndExposesMetrics(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.log")
	outPath := filepath.Join(dir, "siem-out.ndjson")

	initial := strings.Join([]string{
		"Nov 27 10:00:01 bastion-01 sshd[101]: Failed password for admin from 198.51.100.44 port 5001 ssh2",
		"Nov 27 10:00:02 bastion-01 sshd[102]: Failed password for admin from 198.51.100.44 port 5002 ssh2",
		"Nov 27 10:00:03 bastion-01 sshd[103]: Failed password for admin from 198.51.100.44 port 5003 ssh2",
		"",
	}, "\n")
	if err := os.WriteFile(authPath, []byte(initial), 0o600); err != nil {
		t.Fatalf("write initial auth.log: %v", err)
	}

	var buf bytes.Buffer
	pol := policy.DefaultPolicy()
	pol.AuthBurstThreshold = 5

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Append 2 more failures + 1 tamper line after cycle 1, then truncate file (rotation) and write another tamper
	addrCh := make(chan string, 1)
	doneCh := make(chan WatchStats, 1)
	errCh := make(chan error, 1)

	go func() {
		stats, err := RunWatch(ctx, WatchConfig{
			Paths:        []string{authPath},
			Format:       "auth",
			Policy:       pol,
			Interval:     30 * time.Millisecond,
			MaxCycles:    8,
			SIEMOut:      outPath,
			MetricsAddr:  "127.0.0.1:0",
			DryRunAlerts: true,
			OutputFormat: report.FormatNDJSON,
			OnListen: func(addr string) {
				addrCh <- addr
			},
		}, &buf)
		if err != nil {
			errCh <- err
			return
		}
		doneCh <- stats
	}()

	addr := <-addrCh
	time.Sleep(80 * time.Millisecond)

	// Append additional lines to trigger SIEM-001 (5 failures)
	f, err := os.OpenFile(authPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	_, _ = f.WriteString(
		"Nov 27 10:00:04 bastion-01 sshd[104]: Failed password for admin from 198.51.100.44 port 5004 ssh2\n" +
			"Nov 27 10:00:05 bastion-01 sshd[105]: Failed password for admin from 198.51.100.44 port 5005 ssh2\n",
	)
	_ = f.Close()

	time.Sleep(80 * time.Millisecond)

	// Truncate and rotate to verify offset reset & rotation counter
	rotated := "Nov 27 10:05:00 bastion-01 sudo[200]: history -c attempted by guest\n"
	if err := os.WriteFile(authPath, []byte(rotated), 0o600); err != nil {
		t.Fatalf("truncate rotate: %v", err)
	}

	// Verify /metrics responds before watch finishes
	resp, mErr := http.Get("http://" + addr + "/metrics")
	if mErr != nil {
		t.Fatalf("GET /metrics failed: %v", mErr)
	}
	mBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(mBody), "raksa_siem_events_total") {
		t.Fatalf("unexpected /metrics output: %s", string(mBody))
	}

	select {
	case err := <-errCh:
		t.Fatalf("RunWatch failed: %v", err)
	case stats := <-doneCh:
		if stats.LinesRead < 6 || stats.FindingsEmitted == 0 || stats.Rotations == 0 {
			t.Fatalf("unexpected watch stats: %+v\nout=%s", stats, buf.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for RunWatch")
	}

	siemBytes, err := os.ReadFile(outPath)
	if err != nil || !strings.Contains(string(siemBytes), "SIEM-001") {
		t.Fatalf("expected SIEM-001 in %s: err=%v body=%s", outPath, err, string(siemBytes))
	}
}
