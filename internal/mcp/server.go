package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-siem/internal/correlator"
	"github.com/luminariadev/raksa-siem/internal/intel"
	"github.com/luminariadev/raksa-siem/internal/normalizer"
	"github.com/luminariadev/raksa-siem/internal/policy"
	"github.com/luminariadev/raksa-siem/internal/router"
	"github.com/luminariadev/raksa-siem/internal/schema"
	"github.com/luminariadev/raksa-siem/internal/sigma"
)

const (
	// MaxLineBytes bounds incoming JSON-RPC frames at 2 MiB.
	MaxLineBytes = 2 << 20
	// ProtocolVersion is the MCP specification date implemented by raksa-siem.
	ProtocolVersion = "2024-11-05"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// Server exposes raksa-siem capabilities over stdio JSON-RPC 2.0 (MCP).
type Server struct {
	mu        sync.Mutex
	pol       policy.Policy
	tracker   *router.SuppressionTracker
	incidents []schema.Finding
}

// New constructs an MCP Server using the supplied validated policy.
func New(pol policy.Policy) *Server {
	if err := pol.ValidateAndCompile(); err != nil {
		pol = policy.DefaultPolicy()
	}
	return &Server{
		pol:     pol,
		tracker: router.NewSuppressionTracker(pol.SuppressionDuration()),
	}
}

// Serve reads newline-delimited JSON-RPC 2.0 frames from r and writes responses to w.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), MaxLineBytes)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		respBytes, shouldReply := s.HandleLine(line)
		if !shouldReply {
			continue
		}
		if _, err := w.Write(append(respBytes, '\n')); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP frame: %w", err)
	}
	return nil
}

// HandleLine dispatches one JSON-RPC 2.0 request frame and returns encoded JSON bytes.
func (s *Server) HandleLine(line []byte) ([]byte, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		out, _ := json.Marshal(rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: -32700, Message: "parse error: " + err.Error()},
		})
		return out, true
	}

	isNotification := len(bytes.TrimSpace(req.ID)) == 0 || bytes.Equal(bytes.TrimSpace(req.ID), []byte("null"))
	if req.Method == "notifications/initialized" || (strings.HasPrefix(req.Method, "notifications/") && isNotification) {
		return nil, false
	}

	resp := rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    schema.ToolName,
				"version": schema.Version,
			},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{
			"tools": s.toolDefinitions(),
		}
	case "tools/call":
		var p toolCallParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
		} else {
			resp.Result = s.callTool(p.Name, p.Arguments)
		}
	default:
		if isNotification {
			return nil, false
		}
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}

	if isNotification && resp.Error == nil {
		return nil, false
	}
	out, _ := json.Marshal(resp)
	return out, true
}

func (s *Server) toolDefinitions() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "siem_list_rules",
			Description: "List all 23 built-in SIEM correlation rules with metadata and MITRE D3FEND mappings.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"module": map[string]any{"type": "string", "description": "Optional module filter: auth, web-net, correlation, ops, custom, policy"},
				},
			},
		},
		{
			Name:        "siem_analyze_logs",
			Description: "Normalize and correlate multi-format security logs (including .gz, Sigma, sequence, STIX 2.1/CIDR, and asset tiers) and return Raksa Finding Schema v1 report.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":               map[string]any{"type": "string", "description": "Log file or directory path"},
					"paths":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"content":            map[string]any{"type": "string", "description": "Inline raw log or report content"},
					"format":             map[string]any{"type": "string", "description": "auto, raksa, raksa-ndjson, auth, syslog, nginx, jsonl, cef, auditd, cloudtrail, k8s-audit, suricata, win-evtx, leef"},
					"policy_path":        map[string]any{"type": "string", "description": "Optional .raksa-siem.yml policy file"},
					"sigma_paths":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"threat_intel_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"asset_paths":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
			},
		},
		{
			Name:        "siem_correlate_reports",
			Description: "Correlate upstream Raksa Layer 1-5 Finding Schema v1 JSON/NDJSON reports into SIEM incidents.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"paths":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"policy_path":        map[string]any{"type": "string"},
					"sigma_paths":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"threat_intel_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
			},
		},
		{
			Name:        "siem_normalize_events",
			Description: "Parse raw multi-format logs into canonical Raksa SIEM Event records without running correlation.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":    map[string]any{"type": "string"},
					"content": map[string]any{"type": "string"},
					"format":  map[string]any{"type": "string"},
					"limit":   map[string]any{"type": "integer"},
				},
			},
		},
		{
			Name:        "siem_build_timeline",
			Description: "Build a chronological cross-layer attack timeline filtered by src_ip, host, user, or layer.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":    map[string]any{"type": "string"},
					"paths":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"content": map[string]any{"type": "string"},
					"format":  map[string]any{"type": "string"},
					"src_ip":  map[string]any{"type": "string"},
					"host":    map[string]any{"type": "string"},
					"user":    map[string]any{"type": "string"},
					"layer":   map[string]any{"type": "string"},
					"limit":   map[string]any{"type": "integer"},
				},
			},
		},
		{
			Name:        "siem_verify_rules",
			Description: "Fail-closed validation of .raksa-siem.yml policies, regex custom rules, waivers, and sink URLs.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"policy_path": map[string]any{"type": "string"},
				},
				"required": []string{"policy_path"},
			},
		},
		{
			Name:        "siem_check_suppression",
			Description: "Check and record whether a (rule_id, group_key) alert is active or suppressed within cooldown window.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_id":   map[string]any{"type": "string"},
					"group_key": map[string]any{"type": "string"},
				},
				"required": []string{"rule_id", "group_key"},
			},
		},
		{
			Name:        "siem_query_incidents",
			Description: "Query retained session incidents or an NDJSON SIEM store filtered by severity, rule_id, host, or src_ip.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity":   map[string]any{"type": "string"},
					"rule_id":    map[string]any{"type": "string"},
					"host":       map[string]any{"type": "string"},
					"src_ip":     map[string]any{"type": "string"},
					"store_path": map[string]any{"type": "string"},
					"limit":      map[string]any{"type": "integer"},
				},
			},
		},
		{
			Name:        "siem_verify_sigma",
			Description: "Compile and fail-closed validate native Sigma YAML rule files or directories.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string"},
					"paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
			},
		},
		{
			Name:        "siem_match_threat_intel",
			Description: "Match normalized telemetry events or IOC observables against STIX 2.1 JSON, CSV, or CIDR threat feeds.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"threat_intel_paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"path":               map[string]any{"type": "string"},
					"content":            map[string]any{"type": "string"},
					"format":             map[string]any{"type": "string"},
					"src_ip":             map[string]any{"type": "string"},
					"host":               map[string]any{"type": "string"},
				},
				"required": []string{"threat_intel_paths"},
			},
		},
	}
}

func (s *Server) callTool(name string, args map[string]any) toolCallResult {
	switch name {
	case "siem_list_rules":
		mod := strArg(args, "module")
		rules := schema.RuleCatalog(mod)
		return okJSON(map[string]any{"count": len(rules), "rules": rules})

	case "siem_analyze_logs":
		return s.toolAnalyze(args, false)

	case "siem_correlate_reports":
		return s.toolAnalyze(args, true)

	case "siem_normalize_events":
		normFmt, err := parseFormatOrDefault(strArg(args, "format"), normalizer.FormatAuto)
		if err != nil {
			return errTool(err.Error())
		}
		events, stats, err := loadEventsFromArgs(args, normFmt)
		if err != nil {
			return errTool(err.Error())
		}
		limit := intArg(args, "limit", 200)
		if limit > 0 && len(events) > limit {
			events = events[:limit]
		}
		return okJSON(map[string]any{"stats": stats, "count": len(events), "events": events})

	case "siem_build_timeline":
		normFmt, err := parseFormatOrDefault(strArg(args, "format"), normalizer.FormatAuto)
		if err != nil {
			return errTool(err.Error())
		}
		events, _, err := loadEventsFromArgs(args, normFmt)
		if err != nil {
			return errTool(err.Error())
		}
		tl := correlator.BuildTimeline(events, correlator.TimelineFilter{
			SrcIP: strArg(args, "src_ip"),
			Host:  strArg(args, "host"),
			User:  strArg(args, "user"),
			Layer: strArg(args, "layer"),
			Limit: intArg(args, "limit", 200),
		})
		return okJSON(tl)

	case "siem_verify_rules":
		pPath := strArg(args, "policy_path")
		if pPath == "" {
			return errTool("policy_path is required")
		}
		pol, err := policy.LoadPolicy(pPath)
		if err != nil {
			return errTool(err.Error())
		}
		return okJSON(map[string]any{
			"valid":               true,
			"policy_path":         pPath,
			"custom_rules":        len(pol.CustomRules),
			"routes":              len(pol.Routes),
			"suppressions":        len(pol.Suppressions),
			"suppression_window":  pol.SuppressionWindow,
			"auth_burst":          pol.AuthBurstThreshold,
			"web_probe_threshold": pol.WebProbeThreshold,
		})

	case "siem_check_suppression":
		ruleID := strArg(args, "rule_id")
		groupKey := strArg(args, "group_key")
		if ruleID == "" || groupKey == "" {
			return errTool("rule_id and group_key are required")
		}
		deliver, suppressedCount := s.tracker.Check(ruleID, groupKey, time.Now().UTC())
		return okJSON(map[string]any{
			"rule_id":          ruleID,
			"group_key":        groupKey,
			"deliver":          deliver,
			"suppressed":       !deliver,
			"suppressed_count": suppressedCount,
		})

	case "siem_query_incidents":
		return s.toolQueryIncidents(args)

	case "siem_verify_sigma":
		return s.toolVerifySigma(args)

	case "siem_match_threat_intel":
		return s.toolMatchThreatIntel(args)

	default:
		return errTool("unknown tool: " + name)
	}
}

func (s *Server) toolAnalyze(args map[string]any, forceRaksa bool) toolCallResult {
	pol := s.pol
	if polPath := strArg(args, "policy_path"); polPath != "" {
		loaded, err := policy.LoadPolicy(polPath)
		if err != nil {
			return errTool("load policy: " + err.Error())
		}
		pol = loaded
	}
	if extra := strSliceArg(args, "sigma_paths"); len(extra) > 0 {
		pol.SigmaPaths = append(append([]string(nil), pol.SigmaPaths...), extra...)
	}
	if extra := strSliceArg(args, "threat_intel_paths"); len(extra) > 0 {
		pol.ThreatIntelPaths = append(append([]string(nil), pol.ThreatIntelPaths...), extra...)
	}
	if extra := strSliceArg(args, "asset_paths"); len(extra) > 0 {
		pol.AssetPaths = append(append([]string(nil), pol.AssetPaths...), extra...)
	}
	if err := pol.ValidateAndCompile(); err != nil {
		return errTool("compile policy overlays: " + err.Error())
	}

	defFmt := normalizer.FormatAuto
	if forceRaksa {
		defFmt = normalizer.FormatRaksa
	}
	normFmt, err := parseFormatOrDefault(strArg(args, "format"), defFmt)
	if err != nil {
		return errTool(err.Error())
	}
	events, stats, err := loadEventsFromArgs(args, normFmt)
	if err != nil {
		return errTool(err.Error())
	}

	rawFindings, tl := correlator.AnalyzeBatch(events, pol)
	filtered, suppressed := policy.ApplyPolicy(rawFindings, pol)

	s.mu.Lock()
	s.incidents = append(s.incidents, filtered...)
	if len(s.incidents) > 5000 {
		s.incidents = s.incidents[len(s.incidents)-5000:]
	}
	s.mu.Unlock()

	rep := schema.NewReport(filtered)
	return okJSON(map[string]any{
		"report":     rep,
		"suppressed": suppressed,
		"stats":      stats,
		"timeline_summary": map[string]any{
			"total_events": tl.TotalEvents,
			"by_layer":     tl.ByLayer,
		},
	})
}

func (s *Server) toolQueryIncidents(args map[string]any) toolCallResult {
	var minSev schema.Severity
	if rawSev := strArg(args, "severity"); rawSev != "" {
		parsed, err := schema.ParseSeverity(rawSev)
		if err != nil {
			return errTool(err.Error())
		}
		minSev = parsed
	}
	ruleFilter := strArg(args, "rule_id")
	hostFilter := strArg(args, "host")
	srcIPFilter := strArg(args, "src_ip")
	storePath := strArg(args, "store_path")
	limit := intArg(args, "limit", 100)

	var source []schema.Finding
	if storePath != "" {
		loaded, err := loadFindingsFromStore(storePath)
		if err != nil {
			return errTool(err.Error())
		}
		source = loaded
	} else {
		s.mu.Lock()
		source = append(source, s.incidents...)
		s.mu.Unlock()
	}

	var matched []schema.Finding
	for _, f := range source {
		if minSev != "" && !f.Severity.MeetsThreshold(minSev) {
			continue
		}
		if ruleFilter != "" && !strings.EqualFold(f.RuleID, ruleFilter) {
			continue
		}
		if hostFilter != "" && !evidenceMatches(f, "host", hostFilter) && !strings.Contains(strings.ToLower(f.Target), strings.ToLower(hostFilter)) {
			continue
		}
		if srcIPFilter != "" && !evidenceMatches(f, "src_ip", srcIPFilter) && !strings.Contains(f.Target, srcIPFilter) {
			continue
		}
		matched = append(matched, f)
	}
	correlator.SortFindings(matched)
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	return okJSON(map[string]any{"total": len(matched), "findings": matched})
}

func loadFindingsFromStore(path string) ([]schema.Finding, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var out []schema.Finding
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), MaxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var env struct {
			Kind    string          `json:"kind"`
			Finding *schema.Finding `json:"finding"`
		}
		if json.Unmarshal([]byte(line), &env) == nil && env.Finding != nil {
			out = append(out, *env.Finding)
			continue
		}
		var direct schema.Finding
		if json.Unmarshal([]byte(line), &direct) == nil && direct.RuleID != "" {
			out = append(out, direct)
		}
	}
	return out, scanner.Err()
}

func loadEventsFromArgs(args map[string]any, format string) ([]schema.Event, normalizer.ParseStats, error) {
	if content := strArg(args, "content"); content != "" {
		return normalizer.ParseBytes([]byte(content), format, "mcp-inline")
	}

	var paths []string
	if single := strArg(args, "path"); single != "" {
		paths = append(paths, single)
	}
	if rawArr, ok := args["paths"].([]any); ok {
		for _, v := range rawArr {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				paths = append(paths, strings.TrimSpace(s))
			}
		}
	}
	if len(paths) == 0 {
		return nil, normalizer.ParseStats{}, fmt.Errorf("provide path, paths, or content")
	}

	var allEvents []schema.Event
	var totalStats normalizer.ParseStats
	files, err := ExpandInputFiles(paths)
	if err != nil {
		return nil, totalStats, err
	}
	for _, fpath := range files {
		raw, err := os.ReadFile(fpath)
		if err != nil {
			return nil, totalStats, fmt.Errorf("read %q: %w", fpath, err)
		}
		evs, st, err := normalizer.ParseBytes(raw, format, fpath)
		if err != nil {
			return nil, totalStats, fmt.Errorf("parse %q: %w", fpath, err)
		}
		allEvents = append(allEvents, evs...)
		totalStats.LinesRead += st.LinesRead
		totalStats.EventsParsed += st.EventsParsed
		totalStats.SkippedLines += st.SkippedLines
	}
	return allEvents, totalStats, nil
}

// ExpandInputFiles resolves files and directories (non-recursive 1-level + recursive walk) to concrete files.
func ExpandInputFiles(paths []string) ([]string, error) {
	seen := make(map[string]bool)
	var files []string
	for _, raw := range paths {
		clean := filepath.Clean(raw)
		info, err := os.Stat(clean)
		if err != nil {
			return nil, fmt.Errorf("stat %q: %w", raw, err)
		}
		if !info.IsDir() {
			if !seen[clean] {
				seen[clean] = true
				files = append(files, clean)
			}
			continue
		}
		err = filepath.WalkDir(clean, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			switch ext {
			case ".log", ".json", ".ndjson", ".jsonl", ".txt", ".cef", ".gz":
				if !seen[p] {
					seen[p] = true
					files = append(files, p)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no readable log or report files found in %v", paths)
	}
	return files, nil
}

func parseFormatOrDefault(raw, def string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	return normalizer.ParseFormat(raw)
}

func (s *Server) toolVerifySigma(args map[string]any) toolCallResult {
	paths := strSliceArg(args, "paths")
	if p := strArg(args, "path"); p != "" {
		paths = append([]string{p}, paths...)
	}
	if len(paths) == 0 {
		return errTool("provide path or paths to Sigma YAML file/directory")
	}
	var all []*sigma.Rule
	for _, p := range paths {
		rules, err := sigma.LoadPath(p)
		if err != nil {
			return errTool(err.Error())
		}
		all = append(all, rules...)
	}
	return okJSON(map[string]any{
		"valid": true,
		"count": len(all),
		"rules": all,
	})
}

func (s *Server) toolMatchThreatIntel(args map[string]any) toolCallResult {
	feedPaths := strSliceArg(args, "threat_intel_paths")
	if len(feedPaths) == 0 {
		return errTool("threat_intel_paths is required")
	}
	feed := intel.NewThreatFeed()
	for _, p := range feedPaths {
		if err := feed.LoadFile(p); err != nil {
			return errTool(err.Error())
		}
	}

	var events []schema.Event
	if strArg(args, "content") != "" || strArg(args, "path") != "" || len(strSliceArg(args, "paths")) > 0 {
		normFmt, err := parseFormatOrDefault(strArg(args, "format"), normalizer.FormatAuto)
		if err != nil {
			return errTool(err.Error())
		}
		loaded, _, err := loadEventsFromArgs(args, normFmt)
		if err != nil {
			return errTool(err.Error())
		}
		events = loaded
	} else {
		events = []schema.Event{{
			ID:        "mcp-probe",
			Timestamp: time.Now().UTC(),
			SrcIP:     strArg(args, "src_ip"),
			Host:      strArg(args, "host"),
		}}
	}

	var hits []map[string]any
	for _, ev := range events {
		for _, m := range feed.MatchEvent(ev) {
			hits = append(hits, map[string]any{
				"event_id":  ev.ID,
				"indicator": m.Indicator.Value,
				"kind":      m.Indicator.Kind,
				"severity":  m.Indicator.Severity,
				"source":    m.Indicator.Source,
				"matched":   m.MatchedOn,
				"value":     m.MatchedVal,
			})
		}
	}
	return okJSON(map[string]any{
		"indicators_loaded": feed.Count(),
		"events_checked":    len(events),
		"match_count":       len(hits),
		"matches":           hits,
	})
}

func strSliceArg(args map[string]any, key string) []string {
	if args == nil {
		return nil
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range arr {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func strArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func intArg(args map[string]any, key string, def int) int {
	if args == nil {
		return def
	}
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch n := v.(type) {
	case float64:
		if int(n) > 0 {
			return int(n)
		}
	case int:
		if n > 0 {
			return n
		}
	}
	return def
}

func evidenceMatches(f schema.Finding, key, wanted string) bool {
	if f.Evidence == nil {
		return false
	}
	val, ok := f.Evidence[key]
	if !ok {
		return false
	}
	return strings.EqualFold(fmt.Sprint(val), wanted)
}

func okJSON(payload any) toolCallResult {
	b, _ := json.MarshalIndent(payload, "", "  ")
	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: string(b)}},
	}
}

func errTool(msg string) toolCallResult {
	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: msg}},
		IsError: true,
	}
}
