package tailer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luminariadev/raksa-siem/internal/correlator"
	"github.com/luminariadev/raksa-siem/internal/normalizer"
	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/report"
	"github.com/luminariadev/raksa-siem/internal/router"
	"github.com/luminariadev/raksa-siem/internal/schema"
)

// WatchConfig controls continuous multi-file log tailing and correlation.
type WatchConfig struct {
	Paths        []string
	Format       string
	Policy       policy.Policy
	Interval     time.Duration
	Once         bool
	MaxCycles    int
	StartAtEnd   bool
	SIEMOut      string
	MetricsAddr  string
	DryRunAlerts bool
	OutputFormat report.OutputFormat
	OnListen     func(addr string)
}

// WatchStats summarizes counters accumulated during a watch run.
type WatchStats struct {
	Cycles          int `json:"cycles"`
	FilesTracked    int `json:"files_tracked"`
	LinesRead       int `json:"lines_read"`
	EventsParsed    int `json:"events_parsed"`
	FindingsEmitted int `json:"findings_emitted"`
	SuppressedCount int `json:"suppressed_count"`
	Rotations       int `json:"rotations"`
	Errors          int `json:"errors"`
}

type fileState struct {
	offset    int64
	remainder string
}

type metricsCounters struct {
	cycles     atomic.Int64
	events     atomic.Int64
	findings   atomic.Int64
	suppressed atomic.Int64
	rotations  atomic.Int64
	errors     atomic.Int64
}

// RunWatch continuously tails configured log files or directories, feeds new lines
// through the normalizer -> correlator -> policy -> router pipeline, and writes alerts.
func RunWatch(ctx context.Context, cfg WatchConfig, out io.Writer) (WatchStats, error) {
	if len(cfg.Paths) == 0 {
		return WatchStats{}, errors.New("at least one path is required for watch")
	}
	pol := cfg.Policy
	if err := pol.ValidateAndCompile(); err != nil {
		return WatchStats{}, err
	}
	format := cfg.Format
	if strings.TrimSpace(format) == "" {
		format = normalizer.FormatAuto
	}
	normFmt, err := normalizer.ParseFormat(format)
	if err != nil {
		return WatchStats{}, err
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 500 * time.Millisecond
	}
	outFmt := cfg.OutputFormat
	if outFmt == "" {
		outFmt = report.FormatNDJSON
	}

	engine := correlator.NewEngine(pol)
	rt := router.NewRouter(pol, cfg.DryRunAlerts)
	states := make(map[string]*fileState)
	counters := &metricsCounters{}
	var stats WatchStats

	var metricsSrv *http.Server
	if strings.TrimSpace(cfg.MetricsAddr) != "" {
		var ln net.Listener
		ln, metricsSrv, err = startMetricsServer(cfg.MetricsAddr, counters)
		if err != nil {
			return WatchStats{}, err
		}
		if cfg.OnListen != nil {
			cfg.OnListen(ln.Addr().String())
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
	}

	defaultYear := time.Now().UTC().Year()

	for {
		if ctx.Err() != nil {
			break
		}

		files := expandWatchTargets(cfg.Paths)
		stats.FilesTracked = len(files)

		var batchFindings []schema.Finding
		for _, path := range files {
			lines, rotated, readErr := readNewLines(path, states, cfg.StartAtEnd)
			if rotated {
				stats.Rotations++
				counters.rotations.Add(1)
			}
			if readErr != nil {
				stats.Errors++
				counters.errors.Add(1)
				continue
			}
			for _, line := range lines {
				stats.LinesRead++
				evs, ok := normalizer.ParseLine(line, normFmt, defaultYear)
				if !ok {
					continue
				}
				for i := range evs {
					evs[i].Metadata = mergeSourceMeta(evs[i].Metadata, path)
					stats.EventsParsed++
					counters.events.Add(1)
					emitted := engine.Ingest(evs[i])
					batchFindings = append(batchFindings, emitted...)
				}
			}
		}

		if len(batchFindings) > 0 {
			filtered, suppressedByPol := policy.ApplyPolicy(batchFindings, pol)
			stats.SuppressedCount += suppressedByPol
			if suppressedByPol > 0 {
				counters.suppressed.Add(int64(suppressedByPol))
			}
			if len(filtered) > 0 {
				stats.FindingsEmitted += len(filtered)
				counters.findings.Add(int64(len(filtered)))

				results, _ := rt.Deliver(ctx, filtered)
				for _, res := range results {
					if res.SuppressedCount > 0 {
						stats.SuppressedCount += res.SuppressedCount
						counters.suppressed.Add(int64(res.SuppressedCount))
						break
					}
				}
				if cfg.SIEMOut != "" {
					if err := appendFindingsNDJSON(cfg.SIEMOut, filtered); err != nil {
						stats.Errors++
						counters.errors.Add(1)
					}
				}
				if out != nil {
					rep := schema.NewReport(filtered)
					if err := report.WriteReport(out, rep, outFmt); err != nil {
						return stats, err
					}
				}
			}
		}

		stats.Cycles++
		counters.cycles.Add(1)

		if cfg.Once || (cfg.MaxCycles > 0 && stats.Cycles >= cfg.MaxCycles) {
			break
		}

		timer := time.NewTimer(cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return stats, nil
		case <-timer.C:
		}
	}

	return stats, nil
}

func startMetricsServer(addr string, c *metricsCounters) (net.Listener, *http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"ok","tool":"%s","version":"%s"}`+"\n", schema.ToolName, schema.Version)))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var b strings.Builder
		fmt.Fprintf(&b, "# HELP raksa_siem_watch_cycles_total Total polling cycles executed.\n")
		fmt.Fprintf(&b, "# TYPE raksa_siem_watch_cycles_total counter\n")
		fmt.Fprintf(&b, "raksa_siem_watch_cycles_total %d\n", c.cycles.Load())
		fmt.Fprintf(&b, "# HELP raksa_siem_events_total Total log events normalized during watch.\n")
		fmt.Fprintf(&b, "# TYPE raksa_siem_events_total counter\n")
		fmt.Fprintf(&b, "raksa_siem_events_total %d\n", c.events.Load())
		fmt.Fprintf(&b, "# HELP raksa_siem_findings_total Total correlated findings emitted during watch.\n")
		fmt.Fprintf(&b, "# TYPE raksa_siem_findings_total counter\n")
		fmt.Fprintf(&b, "raksa_siem_findings_total %d\n", c.findings.Load())
		fmt.Fprintf(&b, "# HELP raksa_siem_suppressed_total Total findings suppressed during watch.\n")
		fmt.Fprintf(&b, "# TYPE raksa_siem_suppressed_total counter\n")
		fmt.Fprintf(&b, "raksa_siem_suppressed_total %d\n", c.suppressed.Load())
		fmt.Fprintf(&b, "# HELP raksa_siem_rotations_total Total file truncations or rotations detected.\n")
		fmt.Fprintf(&b, "# TYPE raksa_siem_rotations_total counter\n")
		fmt.Fprintf(&b, "raksa_siem_rotations_total %d\n", c.rotations.Load())
		_, _ = w.Write([]byte(b.String()))
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen metrics %q: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	return ln, srv, nil
}

func expandWatchTargets(inputs []string) []string {
	seen := make(map[string]bool)
	var files []string
	for _, raw := range inputs {
		clean := filepath.Clean(raw)
		info, err := os.Stat(clean)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !seen[clean] {
				seen[clean] = true
				files = append(files, clean)
			}
			continue
		}
		entries, err := os.ReadDir(clean)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			switch ext {
			case ".log", ".json", ".ndjson", ".jsonl", ".txt":
				full := filepath.Join(clean, entry.Name())
				if !seen[full] {
					seen[full] = true
					files = append(files, full)
				}
			}
		}
	}
	sort.Strings(files)
	return files
}

func readNewLines(path string, states map[string]*fileState, startAtEnd bool) ([]string, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	st, exists := states[path]
	rotated := false
	if !exists {
		st = &fileState{}
		if startAtEnd {
			st.offset = info.Size()
		}
		states[path] = st
	} else if info.Size() < st.offset {
		st.offset = 0
		st.remainder = ""
		rotated = true
	}

	if info.Size() <= st.offset {
		return nil, rotated, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, rotated, err
	}
	defer f.Close()

	if _, err := f.Seek(st.offset, io.SeekStart); err != nil {
		return nil, rotated, err
	}
	buf, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil, rotated, err
	}
	st.offset += int64(len(buf))

	combined := st.remainder + string(buf)
	var lines []string
	for {
		idx := strings.IndexByte(combined, '\n')
		if idx < 0 {
			st.remainder = combined
			break
		}
		line := strings.TrimRight(combined[:idx], "\r")
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
		combined = combined[idx+1:]
	}
	return lines, rotated, nil
}

func mergeSourceMeta(meta map[string]any, sourcePath string) map[string]any {
	if meta == nil {
		meta = make(map[string]any)
	}
	if _, ok := meta["source"]; !ok {
		meta["source"] = sourcePath
	}
	return meta
}

func appendFindingsNDJSON(path string, findings []schema.Finding) error {
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
}
