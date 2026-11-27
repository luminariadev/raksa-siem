package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/luminariadev/raksa-siem/internal/correlator"
	"github.com/luminariadev/raksa-siem/internal/mcp"
	"github.com/luminariadev/raksa-siem/internal/normalizer"
	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/report"
	"github.com/luminariadev/raksa-siem/internal/router"
	"github.com/luminariadev/raksa-siem/internal/schema"
	"github.com/luminariadev/raksa-siem/internal/server"
	"github.com/luminariadev/raksa-siem/internal/tailer"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	sub := strings.ToLower(strings.TrimSpace(args[0]))
	rest := args[1:]

	switch sub {
	case "analyze":
		return cmdAnalyze(rest, stdin, stdout, stderr, false)
	case "correlate":
		return cmdAnalyze(rest, stdin, stdout, stderr, true)
	case "normalize":
		return cmdNormalize(rest, stdin, stdout, stderr)
	case "watch":
		return cmdWatch(rest, stdout, stderr)
	case "serve":
		return cmdServe(rest, stdout, stderr)
	case "verify-rules":
		return cmdVerifyRules(rest, stdout, stderr)
	case "test-alert":
		return cmdTestAlert(rest, stdout, stderr)
	case "rules":
		return cmdRules(rest, stdout, stderr)
	case "mcp":
		return cmdMCP(rest, stdin, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%s v%s (schema v%s, layer %s)\n", schema.ToolName, schema.Version, schema.SchemaVersion, schema.LayerName)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: raksa-siem <subcommand> [flags] [paths...]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  analyze       Normalize multi-format logs/reports and correlate SIEM incidents")
	fmt.Fprintln(w, "  correlate     Correlate upstream Raksa Layer 1-5 Finding JSON/NDJSON reports")
	fmt.Fprintln(w, "  normalize     Convert multi-format telemetry into canonical Raksa Event JSON")
	fmt.Fprintln(w, "  watch         Continuously tail log files/dirs and route correlated alerts")
	fmt.Fprintln(w, "  serve         Run authenticated HTTP SIEM ingest & query API server")
	fmt.Fprintln(w, "  verify-rules  Validate .raksa-siem.yml policy, regex rules, waivers, and sinks")
	fmt.Fprintln(w, "  test-alert    Dispatch a synthetic test incident to verify configured sinks")
	fmt.Fprintln(w, "  rules         List all built-in SIEM-001..501 correlation rules")
	fmt.Fprintln(w, "  mcp           Run 8-tool stdio JSON-RPC 2.0 MCP server")
	fmt.Fprintln(w, "  version       Show raksa-siem version and schema metadata")
}

func cmdAnalyze(args []string, stdin io.Reader, stdout, stderr io.Writer, forceRaksa bool) int {
	cmdName := "analyze"
	defaultFmt := normalizer.FormatAuto
	if forceRaksa {
		cmdName = "correlate"
		defaultFmt = normalizer.FormatRaksa
	}

	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	formatStr := fs.String("format", defaultFmt, "input format: auto, raksa, raksa-ndjson, auth, syslog, nginx, jsonl, cef")
	outputStr := fs.String("output", string(report.FormatTable), "output format: table, json, sarif, markdown, ndjson")
	policyPath := fs.String("policy", "", "path to .raksa-siem.yml policy")
	baselinePath := fs.String("baseline", "", "path to SHA-256 baseline file")
	writeBaseline := fs.String("write-baseline", "", "write current findings baseline SHA-256 file")
	failOnStr := fs.String("fail-on", string(schema.SeverityHigh), "exit 1 threshold: info, low, medium, high, critical")

	reordered := reorderFlagsFirst(fs, args)
	if err := fs.Parse(reordered); err != nil {
		return 2
	}

	normFmt, err := normalizer.ParseFormat(*formatStr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	outFmt, err := report.ParseFormat(*outputStr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	failOn, err := schema.ParseSeverity(*failOnStr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	targets := fs.Args()
	firstTarget := "."
	if len(targets) > 0 {
		firstTarget = targets[0]
	}
	pol, _, err := policy.DiscoverPolicy(firstTarget, *policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return 2
	}

	events, err := loadInputEvents(targets, stdin, normFmt)
	if err != nil {
		fmt.Fprintf(stderr, "input error: %v\n", err)
		return 2
	}

	findings, _ := correlator.AnalyzeBatch(events, pol)
	findings, _ = policy.ApplyPolicy(findings, pol)

	if strings.TrimSpace(*baselinePath) != "" {
		base, err := policy.LoadBaseline(*baselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "baseline error: %v\n", err)
			return 2
		}
		findings, _ = policy.ApplyBaseline(findings, base)
	}

	if strings.TrimSpace(*writeBaseline) != "" {
		if err := policy.WriteBaseline(*writeBaseline, findings); err != nil {
			fmt.Fprintf(stderr, "write baseline error: %v\n", err)
			return 2
		}
	}

	rep := schema.NewReport(findings)
	if err := report.WriteReport(stdout, rep, outFmt); err != nil {
		fmt.Fprintf(stderr, "render report error: %v\n", err)
		return 2
	}

	for _, f := range findings {
		if f.Severity.MeetsThreshold(failOn) {
			return 1
		}
	}
	return 0
}

func cmdNormalize(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("normalize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	formatStr := fs.String("format", normalizer.FormatAuto, "input format")
	limit := fs.Int("limit", 0, "optional max events to output")
	ndjson := fs.Bool("ndjson", false, "emit newline-delimited JSON events instead of array")

	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return 2
	}
	normFmt, err := normalizer.ParseFormat(*formatStr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	events, err := loadInputEvents(fs.Args(), stdin, normFmt)
	if err != nil {
		fmt.Fprintf(stderr, "normalize error: %v\n", err)
		return 2
	}
	if *limit > 0 && len(events) > *limit {
		events = events[:*limit]
	}

	if *ndjson {
		for _, ev := range events {
			raw, _ := json.Marshal(ev)
			_, _ = stdout.Write(append(raw, '\n'))
		}
		return 0
	}
	raw, _ := json.MarshalIndent(events, "", "  ")
	_, _ = stdout.Write(append(raw, '\n'))
	return 0
}

func cmdWatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	formatStr := fs.String("format", normalizer.FormatAuto, "input log format")
	policyPath := fs.String("policy", "", "policy file path")
	interval := fs.Duration("interval", 500*time.Millisecond, "poll interval")
	once := fs.Bool("once", false, "run one pass and exit")
	maxCycles := fs.Int("max-cycles", 0, "stop after N poll cycles")
	startAtEnd := fs.Bool("start-at-end", false, "seek to EOF on initial discovery")
	siemOut := fs.String("siem-out", "", "append emitted findings as NDJSON to path")
	metricsAddr := fs.String("metrics-addr", "", "optional Prometheus /metrics bind addr")
	dryRun := fs.Bool("dry-run", false, "simulate alert route delivery without external calls")
	outputStr := fs.String("output", string(report.FormatNDJSON), "output format: ndjson, json, table")

	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "watch requires at least one log file or directory path")
		return 2
	}
	pol, _, err := policy.DiscoverPolicy(paths[0], *policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return 2
	}
	outFmt, err := report.ParseFormat(*outputStr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stats, err := tailer.RunWatch(ctx, tailer.WatchConfig{
		Paths:        paths,
		Format:       *formatStr,
		Policy:       pol,
		Interval:     *interval,
		Once:         *once,
		MaxCycles:    *maxCycles,
		StartAtEnd:   *startAtEnd,
		SIEMOut:      *siemOut,
		MetricsAddr:  *metricsAddr,
		DryRunAlerts: *dryRun,
		OutputFormat: outFmt,
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "watch error: %v\n", err)
		return 2
	}
	if stats.FindingsEmitted > 0 && *once {
		return 1
	}
	return 0
}

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8484", "HTTP listen address")
	policyPath := fs.String("policy", "", "policy file path")
	storePath := fs.String("store", "", "optional NDJSON persistence path")
	apiKeyEnv := fs.String("api-key-env", "", "optional environment variable holding required API key")
	dryRun := fs.Bool("dry-run", false, "simulate alert routes instead of external network posts")

	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return 2
	}
	pol, _, err := policy.DiscoverPolicy(".", *policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return 2
	}
	srv, err := server.New(server.Config{
		Addr:         *addr,
		Policy:       pol,
		StorePath:    *storePath,
		APIKeyEnv:    *apiKeyEnv,
		DryRunAlerts: *dryRun,
	})
	if err != nil {
		fmt.Fprintf(stderr, "serve init error: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "raksa-siem listening on %s\n", *addr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(stderr, "serve error: %v\n", err)
		return 2
	}
	return 0
}

func cmdVerifyRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyFlag := fs.String("policy", "", "policy file path")

	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return 2
	}
	var targets []string
	if strings.TrimSpace(*policyFlag) != "" {
		targets = append(targets, strings.TrimSpace(*policyFlag))
	}
	targets = append(targets, fs.Args()...)
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "verify-rules requires at least one policy/custom-rules file path")
		return 2
	}

	var results []map[string]any
	for _, p := range targets {
		pol, err := policy.LoadPolicy(p)
		if err != nil {
			fmt.Fprintf(stderr, "invalid policy %q: %v\n", p, err)
			return 2
		}
		results = append(results, map[string]any{
			"path":               p,
			"valid":              true,
			"custom_rules":       len(pol.CustomRules),
			"routes":             len(pol.Routes),
			"suppressions":       len(pol.Suppressions),
			"suppression_window": pol.SuppressionWindow,
		})
	}
	raw, _ := json.MarshalIndent(map[string]any{"verified": len(results), "policies": results}, "", "  ")
	_, _ = stdout.Write(append(raw, '\n'))
	return 0
}

func cmdTestAlert(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test-alert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "policy file path")
	dryRun := fs.Bool("dry-run", true, "simulate route delivery cleanly")
	ruleID := fs.String("rule-id", "SIEM-201", "synthetic rule ID")
	sevStr := fs.String("severity", string(schema.SeverityHigh), "synthetic alert severity")
	target := fs.String("target", "ip://198.51.100.10", "synthetic target")
	msg := fs.String("message", "Synthetic test alert from raksa-siem test-alert", "alert description")

	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return 2
	}
	sev, err := schema.ParseSeverity(*sevStr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	pol, _, err := policy.DiscoverPolicy(".", *policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return 2
	}
	ruleMeta, ok := schema.LookupRule(*ruleID)
	title := "Synthetic Alert Verification"
	mod := "cross-layer"
	d3fend := "D3-DA"
	rem := "Verify SIEM alert route connectivity and HMAC signature."
	if ok {
		title = ruleMeta.Title
		mod = ruleMeta.Module
		d3fend = ruleMeta.MitreD3FEND
	}

	synthetic := schema.Finding{
		ID:          "test-alert-1",
		RuleID:      *ruleID,
		Module:      mod,
		Layer:       schema.LayerName,
		Severity:    sev,
		Title:       title,
		Description: *msg,
		Target:      *target,
		Evidence:    map[string]any{"synthetic": true},
		Remediation: rem,
		MitreD3FEND: d3fend,
		Timestamp:   time.Now().UTC(),
	}

	rt := router.NewRouter(pol, *dryRun)
	results, delErr := rt.Deliver(context.Background(), []schema.Finding{synthetic})
	raw, _ := json.MarshalIndent(map[string]any{
		"dry_run": *dryRun,
		"routes":  len(pol.Routes),
		"results": results,
	}, "", "  ")
	_, _ = stdout.Write(append(raw, '\n'))
	if delErr != nil {
		fmt.Fprintf(stderr, "alert delivery error: %v\n", delErr)
		return 2
	}
	return 0
}

func cmdRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	module := fs.String("module", "", "filter by module: auth, web-net, cross-layer, ops, custom, watchlist")
	output := fs.String("output", "table", "output format: table or json")

	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return 2
	}
	rules := schema.RuleCatalog(*module)
	if strings.EqualFold(strings.TrimSpace(*output), "json") {
		raw, _ := json.MarshalIndent(rules, "", "  ")
		_, _ = stdout.Write(append(raw, '\n'))
		return 0
	}
	fmt.Fprintf(stdout, "%-10s %-12s %-9s %-9s %s\n", "RULE_ID", "MODULE", "SEVERITY", "D3FEND", "TITLE")
	fmt.Fprintf(stdout, "%-10s %-12s %-9s %-9s %s\n", "-------", "------", "--------", "------", "-----")
	for _, r := range rules {
		fmt.Fprintf(stdout, "%-10s %-12s %-9s %-9s %s\n", r.RuleID, r.Module, r.Severity, r.MitreD3FEND, r.Title)
	}
	return 0
}

func cmdMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "optional policy path")
	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return 2
	}
	pol, _, err := policy.DiscoverPolicy(".", *policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return 2
	}
	if err := mcp.New(pol).Serve(stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "mcp error: %v\n", err)
		return 2
	}
	return 0
}

func loadInputEvents(targets []string, stdin io.Reader, format string) ([]schema.Event, error) {
	if len(targets) == 0 || (len(targets) == 1 && targets[0] == "-") {
		data, err := io.ReadAll(io.LimitReader(stdin, 32<<20))
		if err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			return nil, fmt.Errorf("no input paths provided and stdin is empty")
		}
		evs, _, err := normalizer.ParseBytes(data, format, "stdin")
		return evs, err
	}

	files, err := mcp.ExpandInputFiles(targets)
	if err != nil {
		return nil, err
	}
	var all []schema.Event
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", p, err)
		}
		evs, _, err := normalizer.ParseBytes(raw, format, p)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", p, err)
		}
		all = append(all, evs...)
	}
	return all, nil
}

// reorderFlagsFirst moves known flags and their values before positional arguments
// so callers can run either `raksa-siem analyze --output json path` or `raksa-siem analyze path --output json`.
func reorderFlagsFirst(fs *flag.FlagSet, args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			trimmed := strings.TrimLeft(a, "-")
			if !strings.Contains(trimmed, "=") {
				if f := fs.Lookup(trimmed); f != nil {
					if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
						continue
					}
					if i+1 < len(args) {
						i++
						flags = append(flags, args[i])
					}
				}
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}
