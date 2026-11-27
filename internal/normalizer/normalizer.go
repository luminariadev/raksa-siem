package normalizer

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

const (
	FormatAuto        = "auto"
	FormatRaksa       = "raksa"
	FormatRaksaNDJSON = "raksa-ndjson"
	FormatAuth        = "auth"
	FormatSyslog      = "syslog"
	FormatNginx       = "nginx"
	FormatJSONL       = "jsonl"
	FormatCEF         = "cef"

	maxScannerLineBytes = 2 * 1024 * 1024
	maxEnvelopeBytes    = 16 * 1024 * 1024
)

// ParseStats reports line and format counts observed during normalization.
type ParseStats struct {
	LinesRead    int            `json:"lines_read"`
	EventsParsed int            `json:"events_parsed"`
	SkippedLines int            `json:"skipped_lines"`
	ByFormat     map[string]int `json:"by_format"`
}

// ParseFormat validates an explicit input format selector.
func ParseFormat(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", FormatAuto:
		return FormatAuto, nil
	case FormatRaksa, "json":
		return FormatRaksa, nil
	case FormatRaksaNDJSON, "ndjson":
		return FormatRaksaNDJSON, nil
	case FormatAuth, "authlog", "auth.log":
		return FormatAuth, nil
	case FormatSyslog:
		return FormatSyslog, nil
	case FormatNginx, "access", "apache":
		return FormatNginx, nil
	case FormatJSONL:
		return FormatJSONL, nil
	case FormatCEF:
		return FormatCEF, nil
	case FormatAuditd, "audit":
		return FormatAuditd, nil
	case FormatCloudTrail, "aws-cloudtrail":
		return FormatCloudTrail, nil
	case FormatK8sAudit, "k8s", "kubernetes":
		return FormatK8sAudit, nil
	case FormatSuricata, "suricata-eve", "eve":
		return FormatSuricata, nil
	case FormatWinEVTX, "evtx", "windows":
		return FormatWinEVTX, nil
	case FormatLEEF:
		return FormatLEEF, nil
	default:
		return "", fmt.Errorf("unsupported input format %q: expected auto, raksa, raksa-ndjson, auth, syslog, nginx, jsonl, cef, auditd, cloudtrail, k8s-audit, suricata, win-evtx, or leef", raw)
	}
}

var (
	reNginx     = regexp.MustCompile(`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)[^"]*"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?(.*)$`)
	reRFC5424   = regexp.MustCompile(`^(?:<(\d{1,3})>)?\d+\s+(\d{4}-\d{2}-\d{2}T[^\s]+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(?:\[[^\]]*\]|-)\s*(.*)$`)
	reSyslogBSD = regexp.MustCompile(`^(?:<(\d{1,3})>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$`)
	reSyslogISO = regexp.MustCompile(`^(?:<(\d{1,3})>)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$`)
	reIPv4      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	reSSHFailed  = regexp.MustCompile(`Failed\s+(?:password|publickey|none)\s+for\s+(?:invalid user\s+)?([^\s]+)\s+from\s+(\S+)`)
	reSSHInvalid = regexp.MustCompile(`Invalid user\s+([^\s]*)\s*from\s+(\S+)`)
	reSSHAccept  = regexp.MustCompile(`Accepted\s+(?:password|publickey|keyboard-interactive[^\s]*)\s+for\s+([^\s]+)\s+from\s+(\S+)`)
	reSudoUser   = regexp.MustCompile(`^(\S+)\s*:.*?(?:USER=([^\s;]+))?.*?COMMAND=(.+)$`)
	reSudoFail   = regexp.MustCompile(`(?:authentication failure|NOT in sudoers|incorrect password attempts).*?(?:user=([^\s;]+))?`)
	reRHost      = regexp.MustCompile(`rhost=([^\s;]+)`)
	reUserAdd    = regexp.MustCompile(`(?:new user:\s*name=([^,\s]+)|add\s+'([^']+)'\s+to\s+group\s+'([^']+)')`)

	reWebProbe = regexp.MustCompile(`(?i)(?:\.\./|\.\.%2f|union\s+select|<script|javascript:|%3cscript|eval\s*\(|/\.env|/wp-login\.php|/phpmyadmin|sqlmap|nikto|\bexec\s*\(|cmd\.exe|/bin/sh)`)
	reTamper   = regexp.MustCompile(`(?i)(?:\bhistory\s+-c\b|rm\s+-rf\s+/var/log|truncate\s+-s\s*0\s+/var/log|(?:service|systemctl)\s+stop\s+(?:auditd|rsyslog|syslog)|/dev/null\s*>\s*/var/log)`)
)

// ParseReader normalizes either a full Raksa JSON report envelope or line-delimited telemetry from r.
func ParseReader(r io.Reader, format string, sourceName string) ([]schema.Event, ParseStats, error) {
	normFmt, err := ParseFormat(format)
	if err != nil {
		return nil, ParseStats{}, err
	}
	stats := ParseStats{ByFormat: make(map[string]int)}
	rawBytes, err := io.ReadAll(io.LimitReader(r, maxEnvelopeBytes+1))
	if err != nil {
		return nil, stats, fmt.Errorf("read telemetry %s: %w", sourceName, err)
	}
	rawBytes, err = decompressIfGzip(rawBytes, sourceName)
	if err != nil {
		return nil, stats, err
	}
	if len(rawBytes) <= maxEnvelopeBytes {
		trimmed := bytes.TrimSpace(rawBytes)
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') &&
			(normFmt == FormatAuto || normFmt == FormatRaksa) {
			if evs, matched := tryParseRaksaEnvelope(trimmed, sourceName); matched {
				stats.LinesRead = strings.Count(string(trimmed), "\n") + 1
				stats.EventsParsed = len(evs)
				stats.ByFormat[FormatRaksa] = len(evs)
				return evs, stats, nil
			}
		}
		if len(trimmed) > 0 && trimmed[0] == '{' {
			if evs, matched := tryParseEnterpriseEnvelope(trimmed, normFmt, sourceName); matched {
				stats.LinesRead = strings.Count(string(trimmed), "\n") + 1
				stats.EventsParsed = len(evs)
				stats.ByFormat[FormatCloudTrail] = len(evs)
				return evs, stats, nil
			}
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(rawBytes))
	buf := make([]byte, 64*1024)
	sc.Buffer(buf, maxScannerLineBytes)

	var out []schema.Event
	defaultYear := time.Now().UTC().Year()
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		stats.LinesRead++
		evs, ok := ParseLine(line, normFmt, defaultYear)
		if !ok || len(evs) == 0 {
			stats.SkippedLines++
			continue
		}
		for i := range evs {
			if evs[i].Metadata == nil {
				evs[i].Metadata = make(map[string]any)
			}
			if sourceName != "" {
				evs[i].Metadata["source_name"] = sourceName
			}
			stats.ByFormat[evs[i].SourceFormat]++
		}
		stats.EventsParsed += len(evs)
		out = append(out, evs...)
	}
	if err := sc.Err(); err != nil {
		return out, stats, fmt.Errorf("scan %s: %w", sourceName, err)
	}
	return out, stats, nil
}

// ParseBytes normalizes raw byte content according to format.
func ParseBytes(data []byte, format string, sourceName string) ([]schema.Event, ParseStats, error) {
	return ParseReader(bytes.NewReader(data), format, sourceName)
}

func tryParseRaksaEnvelope(trimmed []byte, sourceName string) ([]schema.Event, bool) {
	if trimmed[0] == '{' {
		var rep schema.Report
		if err := json.Unmarshal(trimmed, &rep); err == nil && (rep.SchemaVersion == schema.SchemaVersion || rep.Tool != "") && rep.Findings != nil {
			out := make([]schema.Event, 0, len(rep.Findings))
			for _, f := range rep.Findings {
				ev := FindingToEvent(f, rep.Tool, sourceName)
				out = append(out, ev)
			}
			return out, true
		}
		return nil, false
	}
	if trimmed[0] == '[' {
		var list []schema.Finding
		if err := json.Unmarshal(trimmed, &list); err == nil && len(list) > 0 && list[0].RuleID != "" {
			out := make([]schema.Event, 0, len(list))
			for _, f := range list {
				out = append(out, FindingToEvent(f, "", sourceName))
			}
			return out, true
		}
	}
	return nil, false
}

// FindingToEvent converts a Raksa Finding Schema v1 record into a canonical SIEM Event.
func FindingToEvent(f schema.Finding, reportTool, sourceName string) schema.Event {
	tool := strings.TrimSpace(reportTool)
	if tool == "" {
		tool = inferToolFromRule(f.RuleID, f.Layer)
	}
	layer := strings.TrimSpace(f.Layer)
	if layer == "" {
		layer = inferLayerFromTool(tool)
	}
	ts := f.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sev := f.Severity
	if sev == "" {
		sev = schema.SeverityMedium
	}

	ev := schema.Event{
		ID:           f.ID,
		Timestamp:    ts.UTC(),
		SourceFormat: FormatRaksa,
		Layer:        layer,
		Tool:         tool,
		RuleID:       f.RuleID,
		Severity:     sev,
		Category:     inferCategoryFromLayer(layer),
		Action:       "finding",
		Outcome:      "alert",
		Message:      strings.TrimSpace(f.Title + ": " + f.Description),
		Metadata: map[string]any{
			"module":       f.Module,
			"target":       f.Target,
			"mitre_d3fend": f.MitreD3FEND,
		},
	}
	if sourceName != "" {
		ev.Metadata["source_name"] = sourceName
	}
	if f.Evidence != nil {
		ev.SrcIP = firstMapString(f.Evidence, "src_ip", "source_ip", "client_ip", "remote_ip", "ip")
		ev.DstIP = firstMapString(f.Evidence, "dst_ip", "dest_ip", "bind_addr")
		ev.Host = firstMapString(f.Evidence, "host", "hostname", "asset", "node", "agent_host")
		ev.User = firstMapString(f.Evidence, "user", "username", "account")
		ev.Process = firstMapString(f.Evidence, "process", "binary", "program")
		ev.Path = firstMapString(f.Evidence, "path", "file", "rel_path", "file_path")
		ev.HTTPMethod = firstMapString(f.Evidence, "method", "http_method")
		ev.HTTPPath = firstMapString(f.Evidence, "http_path", "uri", "request_uri")
		if p := firstMapInt(f.Evidence, "dst_port", "port"); p > 0 {
			ev.DstPort = p
		}
		if st := firstMapInt(f.Evidence, "status", "http_status"); st > 0 {
			ev.HTTPStatus = st
		}
		for k, v := range f.Evidence {
			ev.Metadata["ev_"+k] = v
		}
	}
	applyTargetHints(&ev, f.Target)
	if ev.ID == "" {
		ev.ID = deterministicEventID(ev.Layer, ev.RuleID, f.Target, ev.Timestamp.String())
	}
	return ev
}

// ParseLine parses a single line according to format ("auto" detects among all line formats).
func ParseLine(line string, format string, defaultYear int) ([]schema.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, false
	}
	normFmt, err := ParseFormat(format)
	if err != nil {
		return nil, false
	}

	if normFmt == FormatRaksa || normFmt == FormatRaksaNDJSON {
		return parseJSONLine(line, true, normFmt)
	}
	if normFmt == FormatJSONL || normFmt == FormatCloudTrail || normFmt == FormatK8sAudit || normFmt == FormatSuricata || normFmt == FormatWinEVTX {
		return parseJSONLine(line, false, normFmt)
	}
	if normFmt == FormatCEF {
		if ev, ok := parseCEFLine(line, defaultYear); ok {
			return []schema.Event{ev}, true
		}
		return nil, false
	}
	if normFmt == FormatLEEF {
		if ev, ok := parseLEEFLine(line); ok {
			return []schema.Event{ev}, true
		}
		return nil, false
	}
	if normFmt == FormatAuditd {
		if ev, ok := parseAuditdLine(line); ok {
			return []schema.Event{ev}, true
		}
		return nil, false
	}
	if normFmt == FormatNginx {
		if ev, ok := parseNginxLine(line); ok {
			return []schema.Event{ev}, true
		}
		return nil, false
	}
	if normFmt == FormatAuth {
		if ev, ok := parseSyslogOrAuthLine(line, defaultYear, true); ok {
			return []schema.Event{ev}, true
		}
		return nil, false
	}
	if normFmt == FormatSyslog {
		if ev, ok := parseSyslogOrAuthLine(line, defaultYear, false); ok {
			return []schema.Event{ev}, true
		}
		return nil, false
	}

	// Auto-detection order: JSON -> CEF -> LEEF -> Auditd -> Nginx -> Syslog/Auth
	if strings.HasPrefix(line, "{") {
		if evs, ok := parseJSONLine(line, false, FormatAuto); ok {
			return evs, true
		}
	}
	if strings.Contains(line, "CEF:") {
		if ev, ok := parseCEFLine(line, defaultYear); ok {
			return []schema.Event{ev}, true
		}
	}
	if strings.Contains(line, "LEEF:") {
		if ev, ok := parseLEEFLine(line); ok {
			return []schema.Event{ev}, true
		}
	}
	if strings.Contains(line, "msg=audit(") {
		if ev, ok := parseAuditdLine(line); ok {
			return []schema.Event{ev}, true
		}
	}
	if ev, ok := parseNginxLine(line); ok {
		return []schema.Event{ev}, true
	}
	if ev, ok := parseSyslogOrAuthLine(line, defaultYear, false); ok {
		return []schema.Event{ev}, true
	}
	return nil, false
}

func parseJSONLine(line string, requireRaksa bool, normFmt string) ([]schema.Event, bool) {
	if !strings.HasPrefix(line, "{") {
		return nil, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, false
	}

	// 1. Single-line Raksa Report envelope
	if _, hasFindings := raw["findings"]; hasFindings && (raw["schema_version"] == schema.SchemaVersion || raw["tool"] != nil) {
		var rep schema.Report
		if err := json.Unmarshal([]byte(line), &rep); err == nil {
			out := make([]schema.Event, 0, len(rep.Findings))
			for _, f := range rep.Findings {
				out = append(out, FindingToEvent(f, rep.Tool, ""))
			}
			return out, true
		}
	}

	// 2. Single Raksa Finding NDJSON line
	if rid := firstMapString(raw, "rule_id"); rid != "" && raw["layer"] != nil && raw["title"] != nil {
		var f schema.Finding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			ev := FindingToEvent(f, firstMapString(raw, "tool"), "")
			ev.SourceFormat = FormatRaksaNDJSON
			return []schema.Event{ev}, true
		}
	}
	if requireRaksa {
		return nil, false
	}

	// 3. Enterprise JSON schemas (CloudTrail, K8s Audit, Suricata EVE, Windows EVTX JSON)
	if evs, ok := tryParseEnterpriseJSONMap(raw, line, normFmt); ok {
		return evs, true
	}
	if normFmt != FormatAuto && normFmt != FormatJSONL {
		return nil, false
	}

	// 3. Generic JSONL event
	ts := parseFlexibleTime(firstMapString(raw, "timestamp", "ts", "@timestamp", "time"), time.Now().UTC().Year())
	sevStr := strings.ToLower(firstMapString(raw, "severity", "level"))
	sev := schema.SeverityInfo
	if parsed, err := schema.ParseSeverity(sevStr); err == nil {
		sev = parsed
	}
	layer := firstMapString(raw, "layer")
	if layer == "" {
		layer = "telemetry"
	}
	cat := firstMapString(raw, "category", "event_type")
	if cat == "" {
		cat = inferCategoryFromLayer(layer)
	}
	msg := firstMapString(raw, "message", "msg", "detail", "title")
	if msg == "" {
		msg = line
	}
	ev := schema.Event{
		ID:           firstMapString(raw, "id", "event_id"),
		Timestamp:    ts,
		SourceFormat: FormatJSONL,
		Layer:        layer,
		Tool:         firstMapString(raw, "tool", "source"),
		RuleID:       firstMapString(raw, "rule_id"),
		Severity:     sev,
		Category:     cat,
		Action:       defaultString(firstMapString(raw, "action", "event"), "event"),
		Outcome:      defaultString(firstMapString(raw, "outcome", "status_text", "result"), "observed"),
		SrcIP:        firstMapString(raw, "src_ip", "client_ip", "source_ip", "ip", "remote_ip"),
		DstIP:        firstMapString(raw, "dst_ip", "dest_ip"),
		DstPort:      firstMapInt(raw, "dst_port", "port"),
		Host:         firstMapString(raw, "host", "hostname", "node"),
		User:         firstMapString(raw, "user", "username", "account"),
		Process:      firstMapString(raw, "process", "program"),
		Path:         firstMapString(raw, "path", "file", "file_path"),
		HTTPMethod:   firstMapString(raw, "http_method", "method"),
		HTTPPath:     firstMapString(raw, "http_path", "uri", "request_uri"),
		HTTPStatus:   firstMapInt(raw, "http_status", "status"),
		Message:      msg,
		Raw:          line,
	}
	if reTamper.MatchString(ev.Message) {
		ev.Category = "ops"
		ev.Action = "log_tamper"
		if ev.Severity.Rank() < schema.SeverityMedium.Rank() {
			ev.Severity = schema.SeverityMedium
		}
	}
	if ev.ID == "" {
		ev.ID = deterministicEventID(FormatJSONL, ev.Host, ev.SrcIP, ev.Message, ev.Timestamp.String())
	}
	return []schema.Event{ev}, true
}

func parseNginxLine(line string) (schema.Event, bool) {
	m := reNginx.FindStringSubmatch(line)
	if m == nil {
		return schema.Event{}, false
	}
	srcIP, user, tsRaw, method, uri, statusStr, ua, tail := m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]
	status, _ := strconv.Atoi(statusStr)
	ts := parseFlexibleTime(tsRaw, time.Now().UTC().Year())
	if user == "-" {
		user = ""
	}
	host := extractKeyVal(tail, "host=", "vhost=")

	sev := schema.SeverityInfo
	action := "request"
	outcome := "success"
	switch {
	case reWebProbe.MatchString(uri) || reWebProbe.MatchString(ua):
		action = "probe"
		sev = schema.SeverityMedium
		if status == 403 || status == 406 {
			outcome = "blocked"
		} else {
			outcome = "attempt"
		}
	case status == 401 || status == 403 || status == 404:
		outcome = "failure"
		sev = schema.SeverityLow
	case status >= 500:
		action = "server_error"
		outcome = "error"
		sev = schema.SeverityMedium
	}

	ev := schema.Event{
		Timestamp:    ts,
		SourceFormat: FormatNginx,
		Layer:        "web-defense",
		Severity:     sev,
		Category:     "web",
		Action:       action,
		Outcome:      outcome,
		SrcIP:        srcIP,
		Host:         host,
		User:         user,
		HTTPMethod:   method,
		HTTPPath:     uri,
		HTTPStatus:   status,
		Message:      fmt.Sprintf("%s %s -> %d", method, uri, status),
		Raw:          line,
		Metadata:     map[string]any{"user_agent": ua},
	}
	ev.ID = deterministicEventID(FormatNginx, srcIP, method, uri, statusStr, ts.String())
	return ev, true
}

func parseCEFLine(line string, defaultYear int) (schema.Event, bool) {
	idx := strings.Index(line, "CEF:")
	if idx < 0 {
		return schema.Event{}, false
	}
	prefix := strings.TrimSpace(line[:idx])
	cefBody := line[idx+4:]
	parts := splitCEFFields(cefBody, 8)
	if len(parts) < 7 {
		return schema.Event{}, false
	}
	vendor, product, sigID, name, sevRaw := parts[1], parts[2], parts[4], parts[5], parts[6]
	extStr := ""
	if len(parts) > 7 {
		extStr = parts[7]
	}
	exts := parseCEFExtensions(extStr)

	ts := time.Now().UTC()
	if rt := exts["rt"]; rt != "" {
		ts = parseFlexibleTime(rt, defaultYear)
	} else if prefix != "" {
		if m := reSyslogBSD.FindStringSubmatch(prefix + ": x"); m != nil {
			ts = parseFlexibleTime(m[2], defaultYear)
		} else {
			fields := strings.Fields(prefix)
			if len(fields) > 0 {
				ts = parseFlexibleTime(fields[0], defaultYear)
			}
		}
	}

	sev := mapCEFSeverity(sevRaw)
	srcIP := firstMapStringStr(exts, "src", "c6a2", "sourceAddress")
	dstIP := firstMapStringStr(exts, "dst", "c6a3", "destinationAddress")
	dstPort, _ := strconv.Atoi(firstMapStringStr(exts, "dpt", "destinationPort"))
	host := firstMapStringStr(exts, "dhost", "shost", "dvchost")
	user := firstMapStringStr(exts, "duser", "suser")
	msg := firstMapStringStr(exts, "msg")
	if msg == "" {
		msg = name
	}

	layer := "telemetry"
	cat := "alert"
	lowProd := strings.ToLower(vendor + " " + product + " " + name)
	switch {
	case strings.Contains(lowProd, "waf") || strings.Contains(lowProd, "http") || exts["request"] != "":
		layer = "web-defense"
		cat = "web"
	case strings.Contains(lowProd, "firewall") || strings.Contains(lowProd, "ids") || dstPort > 0:
		layer = "network-defense"
		cat = "network"
	case strings.Contains(lowProd, "edr") || strings.Contains(lowProd, "av") || strings.Contains(lowProd, "malware"):
		layer = "ioc-defense"
		cat = "malware"
	}

	ev := schema.Event{
		Timestamp:    ts,
		SourceFormat: FormatCEF,
		Layer:        layer,
		Tool:         strings.TrimSpace(product),
		RuleID:       sigID,
		Severity:     sev,
		Category:     cat,
		Action:       defaultString(firstMapStringStr(exts, "act"), "cef_event"),
		Outcome:      defaultString(firstMapStringStr(exts, "outcome"), "alert"),
		SrcIP:        srcIP,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Host:         host,
		User:         user,
		HTTPPath:     exts["request"],
		Path:         exts["fname"],
		Message:      msg,
		Raw:          line,
	}
	ev.ID = deterministicEventID(FormatCEF, sigID, srcIP, host, msg, ts.String())
	return ev, true
}

func parseSyslogOrAuthLine(line string, defaultYear int, forceAuth bool) (schema.Event, bool) {
	var priStr, tsStr, host, prog, msg string
	if m := reRFC5424.FindStringSubmatch(line); m != nil {
		priStr, tsStr, host, prog, msg = m[1], m[2], m[3], m[4], m[5]
	} else if m := reSyslogISO.FindStringSubmatch(line); m != nil {
		priStr, tsStr, host, prog, msg = m[1], m[2], m[3], m[4], m[6]
	} else if m := reSyslogBSD.FindStringSubmatch(line); m != nil {
		priStr, tsStr, host, prog, msg = m[1], m[2], m[3], m[4], m[6]
	} else {
		return schema.Event{}, false
	}

	ts := parseFlexibleTime(tsStr, defaultYear)
	sev := schema.SeverityInfo
	if priStr != "" {
		if pri, err := strconv.Atoi(priStr); err == nil {
			switch pri & 7 {
			case 0, 1, 2:
				sev = schema.SeverityCritical
			case 3:
				sev = schema.SeverityHigh
			case 4:
				sev = schema.SeverityMedium
			}
		}
	}

	lowProg := strings.ToLower(prog)
	ev := schema.Event{
		Timestamp:    ts,
		SourceFormat: FormatSyslog,
		Layer:        "host-hardening",
		Severity:     sev,
		Category:     "system",
		Action:       "syslog",
		Outcome:      "observed",
		Host:         host,
		Process:      prog,
		Message:      msg,
		Raw:          line,
	}

	isAuthProg := forceAuth || strings.Contains(lowProg, "sshd") || strings.Contains(lowProg, "sudo") ||
		strings.Contains(lowProg, "useradd") || strings.Contains(lowProg, "usermod") ||
		strings.Contains(lowProg, "su") || strings.Contains(lowProg, "pam")

	if isAuthProg {
		ev.SourceFormat = FormatAuth
		ev.Category = "auth"
		switch {
		case reSSHFailed.MatchString(msg):
			sub := reSSHFailed.FindStringSubmatch(msg)
			ev.User = sub[1]
			ev.SrcIP = sub[2]
			ev.Action = "login"
			ev.Outcome = "failure"
			ev.Severity = maxSeverity(ev.Severity, schema.SeverityLow)
		case reSSHInvalid.MatchString(msg):
			sub := reSSHInvalid.FindStringSubmatch(msg)
			ev.User = defaultString(sub[1], "unknown")
			ev.SrcIP = sub[2]
			ev.Action = "login"
			ev.Outcome = "failure"
			ev.Severity = maxSeverity(ev.Severity, schema.SeverityLow)
		case reSSHAccept.MatchString(msg):
			sub := reSSHAccept.FindStringSubmatch(msg)
			ev.User = sub[1]
			ev.SrcIP = sub[2]
			ev.Action = "login"
			ev.Outcome = "success"
		case strings.Contains(lowProg, "sudo") && reSudoFail.MatchString(msg):
			sub := reSudoFail.FindStringSubmatch(msg)
			ev.Category = "privilege"
			ev.Action = "sudo"
			ev.Outcome = "failure"
			ev.User = sub[1]
			if rm := reRHost.FindStringSubmatch(msg); rm != nil {
				ev.SrcIP = rm[1]
			}
			ev.Severity = maxSeverity(ev.Severity, schema.SeverityHigh)
		case strings.Contains(lowProg, "sudo") && reSudoUser.MatchString(msg):
			sub := reSudoUser.FindStringSubmatch(msg)
			ev.Category = "privilege"
			ev.Action = "sudo"
			ev.Outcome = "success"
			ev.User = sub[1]
			cmd := strings.ToLower(sub[3])
			if strings.Contains(cmd, "/bin/sh") || strings.Contains(cmd, "/bin/bash") ||
				strings.Contains(cmd, "useradd") || strings.Contains(cmd, "chmod +s") ||
				strings.Contains(cmd, "visudo") || strings.Contains(cmd, "/etc/shadow") {
				ev.Severity = maxSeverity(ev.Severity, schema.SeverityHigh)
			}
		case reUserAdd.MatchString(msg):
			sub := reUserAdd.FindStringSubmatch(msg)
			ev.Category = "privilege"
			ev.Action = "account_change"
			ev.Outcome = "success"
			ev.User = defaultString(sub[1], sub[2])
			ev.Severity = maxSeverity(ev.Severity, schema.SeverityHigh)
		case strings.Contains(strings.ToLower(msg), "failed su") || strings.Contains(strings.ToLower(msg), "authentication failure"):
			ev.Category = "privilege"
			ev.Action = "su"
			ev.Outcome = "failure"
			ev.Severity = maxSeverity(ev.Severity, schema.SeverityMedium)
		}
	}

	if ev.SrcIP == "" {
		if ip := reIPv4.FindString(msg); ip != "" {
			ev.SrcIP = ip
		}
	}
	if reTamper.MatchString(msg) {
		ev.Category = "ops"
		ev.Action = "log_tamper"
		ev.Severity = maxSeverity(ev.Severity, schema.SeverityMedium)
	}
	ev.ID = deterministicEventID(ev.SourceFormat, ev.Host, ev.Process, ev.SrcIP, ev.Message, ev.Timestamp.String())
	return ev, true
}

func parseFlexibleTime(raw string, defaultYear int) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Now().UTC()
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"02/Jan/2006:15:04:05 -0700",
		"02/Jan/2006:15:04:05 -07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"Jan 2 2006 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC()
		}
	}
	// Unix epoch millis or seconds (CEF rt field)
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(n).UTC()
		}
		if n > 1e9 {
			return time.Unix(n, 0).UTC()
		}
	}
	// BSD syslog timestamp without year: "Nov 27 10:15:01"
	collapsed := strings.Join(strings.Fields(raw), " ")
	withYear := fmt.Sprintf("%d %s", defaultYear, collapsed)
	if parsed, err := time.Parse("2006 Jan 2 15:04:05", withYear); err == nil {
		return parsed.UTC()
	}
	return time.Now().UTC()
}

func applyTargetHints(ev *schema.Event, target string) {
	t := strings.TrimSpace(target)
	if t == "" {
		return
	}
	if strings.HasPrefix(t, "host://") {
		if ev.Host == "" {
			ev.Host = strings.TrimPrefix(t, "host://")
		}
		return
	}
	if strings.HasPrefix(t, "file://") {
		if ev.Path == "" {
			ev.Path = strings.TrimPrefix(t, "file://")
		}
		return
	}
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		h := u.Hostname()
		if ev.DstIP == "" && reIPv4.MatchString(h) {
			ev.DstIP = h
		} else if ev.Host == "" && !reIPv4.MatchString(h) {
			ev.Host = h
		}
		if ev.DstPort == 0 && u.Port() != "" {
			if p, err := strconv.Atoi(u.Port()); err == nil {
				ev.DstPort = p
			}
		}
		if ev.HTTPPath == "" && (u.Scheme == "http" || u.Scheme == "https") && u.Path != "" {
			ev.HTTPPath = u.Path
		}
	}
}

func inferToolFromRule(ruleID, layer string) string {
	switch {
	case strings.HasPrefix(ruleID, "NET-"):
		return "raksa-netguard"
	case strings.HasPrefix(ruleID, "HOST-"):
		return "raksa-hostguard"
	case strings.HasPrefix(ruleID, "WEB-"):
		return "raksa-webshield"
	case strings.HasPrefix(ruleID, "PIPE-"):
		return "raksa-pipeguard"
	case strings.HasPrefix(ruleID, "IOC-"):
		return "raksa-iocscan"
	case strings.HasPrefix(ruleID, "SIEM-"):
		return "raksa-siem"
	default:
		switch layer {
		case "network-defense":
			return "raksa-netguard"
		case "host-hardening":
			return "raksa-hostguard"
		case "web-defense":
			return "raksa-webshield"
		case "devsecops":
			return "raksa-pipeguard"
		case "ioc-defense":
			return "raksa-iocscan"
		}
	}
	return ""
}

func inferLayerFromTool(tool string) string {
	switch strings.ToLower(tool) {
	case "raksa-netguard":
		return "network-defense"
	case "raksa-hostguard":
		return "host-hardening"
	case "raksa-webshield":
		return "web-defense"
	case "raksa-pipeguard":
		return "devsecops"
	case "raksa-iocscan":
		return "ioc-defense"
	case "raksa-siem":
		return "siem"
	default:
		return "telemetry"
	}
}

func inferCategoryFromLayer(layer string) string {
	switch layer {
	case "network-defense":
		return "network"
	case "host-hardening":
		return "host"
	case "web-defense":
		return "web"
	case "devsecops":
		return "devsecops"
	case "ioc-defense":
		return "malware"
	case "siem":
		return "correlation"
	default:
		return "telemetry"
	}
}

func splitCEFFields(body string, maxParts int) []string {
	fields := make([]string, 0, maxParts)
	var cur strings.Builder
	escaped := false
	for i := 0; i < len(body); i++ {
		if len(fields) == maxParts-1 {
			fields = append(fields, body[i:])
			return fields
		}
		c := body[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '|' {
			fields = append(fields, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	fields = append(fields, cur.String())
	return fields
}

func parseCEFExtensions(raw string) map[string]string {
	out := make(map[string]string)
	tokens := strings.Fields(raw)
	curKey := ""
	var curVal strings.Builder
	flush := func() {
		if curKey != "" {
			out[curKey] = strings.TrimSpace(curVal.String())
		}
	}
	for _, tok := range tokens {
		if eq := strings.IndexByte(tok, '='); eq > 0 && isASCIIIdent(tok[:eq]) {
			flush()
			curKey = tok[:eq]
			curVal.Reset()
			curVal.WriteString(tok[eq+1:])
		} else if curKey != "" {
			if curVal.Len() > 0 {
				curVal.WriteByte(' ')
			}
			curVal.WriteString(tok)
		}
	}
	flush()
	return out
}

func isASCIIIdent(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.') {
			return false
		}
	}
	return len(s) > 0
}

func mapCEFSeverity(raw string) schema.Severity {
	raw = strings.TrimSpace(raw)
	if n, err := strconv.Atoi(raw); err == nil {
		switch {
		case n >= 10:
			return schema.SeverityCritical
		case n >= 8:
			return schema.SeverityHigh
		case n >= 6:
			return schema.SeverityMedium
		case n >= 4:
			return schema.SeverityLow
		default:
			return schema.SeverityInfo
		}
	}
	if sev, err := schema.ParseSeverity(raw); err == nil {
		return sev
	}
	return schema.SeverityMedium
}

func extractKeyVal(tail string, keys ...string) string {
	for _, k := range keys {
		idx := strings.Index(tail, k)
		if idx >= 0 {
			rest := tail[idx+len(k):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return strings.Trim(fields[0], `"`)
			}
		}
	}
	return ""
}

func firstMapString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if val, ok := m[k]; ok && val != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", val))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func firstMapStringStr(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func firstMapInt(m map[string]any, keys ...string) int {
	for _, k := range keys {
		val, ok := m[k]
		if !ok || val == nil {
			continue
		}
		switch t := val.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case json.Number:
			if i, err := t.Int64(); err == nil {
				return int(i)
			}
		case string:
			if i, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
				return i
			}
		}
	}
	return 0
}

func defaultString(val, fallback string) string {
	if strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func maxSeverity(a, b schema.Severity) schema.Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

func deterministicEventID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return "ev-" + hex.EncodeToString(h.Sum(nil))[:16]
}
