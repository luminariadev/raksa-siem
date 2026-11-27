package normalizer

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

const (
	FormatAuditd     = "auditd"
	FormatCloudTrail = "cloudtrail"
	FormatK8sAudit   = "k8s-audit"
	FormatSuricata   = "suricata"
	FormatWinEVTX    = "win-evtx"
	FormatLEEF       = "leef"

	maxGzipExpandedBytes = 64 * 1024 * 1024
)

var (
	reAuditdHeader = regexp.MustCompile(`type=([A-Z0-9_]+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)$`)
	reAuditdKV     = regexp.MustCompile(`([A-Za-z0-9_\-]+)=("[^"]*"|\S+)`)
	reSusExec      = regexp.MustCompile(`(?i)(?:/dev/tcp|/bin/nc\b|ncat\b|curl\s+.*\|\s*(?:ba)?sh|base64\s+-d|python3?\s+-c|powershell\s+-enc)`)
)

func decompressIfGzip(raw []byte, sourceName string) ([]byte, error) {
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return raw, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream %s: %w", sourceName, err)
	}
	defer gz.Close()

	expanded, err := io.ReadAll(io.LimitReader(gz, maxGzipExpandedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read gzip stream %s: %w", sourceName, err)
	}
	if len(expanded) > maxGzipExpandedBytes {
		return nil, fmt.Errorf("decompressed gzip telemetry %s exceeds %d byte safety limit", sourceName, maxGzipExpandedBytes)
	}
	return expanded, nil
}

func tryParseEnterpriseEnvelope(trimmed []byte, normFmt, sourceName string) ([]schema.Event, bool) {
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	if normFmt != FormatAuto && normFmt != FormatCloudTrail {
		return nil, false
	}
	var env struct {
		Records []map[string]any `json:"Records"`
	}
	if err := json.Unmarshal(trimmed, &env); err != nil || len(env.Records) == 0 {
		return nil, false
	}
	out := make([]schema.Event, 0, len(env.Records))
	for _, rec := range env.Records {
		if ev, ok := cloudTrailMapToEvent(rec, "", sourceName); ok {
			out = append(out, ev)
		}
	}
	return out, len(out) > 0
}

func tryParseEnterpriseJSONMap(raw map[string]any, line, normFmt string) ([]schema.Event, bool) {
	switch normFmt {
	case FormatCloudTrail:
		if recs, ok := raw["Records"].([]any); ok && len(recs) > 0 {
			var out []schema.Event
			for _, item := range recs {
				if recMap, ok := item.(map[string]any); ok {
					if ev, ok := cloudTrailMapToEvent(recMap, line, ""); ok {
						out = append(out, ev)
					}
				}
			}
			return out, len(out) > 0
		}
		if ev, ok := cloudTrailMapToEvent(raw, line, ""); ok {
			return []schema.Event{ev}, true
		}
		return nil, false

	case FormatK8sAudit:
		if ev, ok := k8sAuditMapToEvent(raw, line); ok {
			return []schema.Event{ev}, true
		}
		return nil, false

	case FormatSuricata:
		if ev, ok := suricataMapToEvent(raw, line); ok {
			return []schema.Event{ev}, true
		}
		return nil, false

	case FormatWinEVTX:
		if ev, ok := winEVTXMapToEvent(raw, line); ok {
			return []schema.Event{ev}, true
		}
		return nil, false
	}

	// Auto-detection for enterprise JSON object schemas
	if _, hasRecords := raw["Records"]; hasRecords {
		if recs, ok := raw["Records"].([]any); ok && len(recs) > 0 {
			var out []schema.Event
			for _, item := range recs {
				if recMap, ok := item.(map[string]any); ok {
					if ev, ok := cloudTrailMapToEvent(recMap, line, ""); ok {
						out = append(out, ev)
					}
				}
			}
			if len(out) > 0 {
				return out, true
			}
		}
	}
	if firstMapString(raw, "eventSource") != "" && firstMapString(raw, "eventName") != "" {
		if ev, ok := cloudTrailMapToEvent(raw, line, ""); ok {
			return []schema.Event{ev}, true
		}
	}
	if firstMapString(raw, "verb") != "" && (raw["objectRef"] != nil || firstMapString(raw, "requestURI") != "" || firstMapString(raw, "kind") == "Event") {
		if ev, ok := k8sAuditMapToEvent(raw, line); ok {
			return []schema.Event{ev}, true
		}
	}
	if firstMapString(raw, "event_type") != "" && (raw["alert"] != nil || raw["dns"] != nil || raw["http"] != nil || raw["flow"] != nil || firstMapString(raw, "dest_ip") != "") {
		if ev, ok := suricataMapToEvent(raw, line); ok {
			return []schema.Event{ev}, true
		}
	}
	if firstMapInt(raw, "EventID", "event_id") > 0 && (firstMapString(raw, "Computer", "Channel", "ProviderName", "TargetUserName", "CommandLine") != "" || raw["EventData"] != nil) {
		if ev, ok := winEVTXMapToEvent(raw, line); ok {
			return []schema.Event{ev}, true
		}
	}
	return nil, false
}

func parseAuditdLine(line string) (schema.Event, bool) {
	m := reAuditdHeader.FindStringSubmatch(line)
	if m == nil {
		return schema.Event{}, false
	}
	recType, epochStr, seqStr, body := m[1], m[2], m[3], m[4]
	kv := make(map[string]string)
	for _, pair := range reAuditdKV.FindAllStringSubmatch(body, -1) {
		kv[strings.ToLower(pair[1])] = strings.Trim(pair[2], `"`)
	}

	ts := time.Now().UTC()
	if secFloat, err := strconv.ParseFloat(epochStr, 64); err == nil {
		sec := int64(secFloat)
		nsec := int64((secFloat - float64(sec)) * 1e9)
		ts = time.Unix(sec, nsec).UTC()
	}

	host := firstMapStringStr(kv, "node", "hostname", "host")
	user := firstMapStringStr(kv, "acct", "auid", "euid", "uid")
	proc := firstMapStringStr(kv, "comm", "exe")
	srcIP := firstMapStringStr(kv, "addr")
	if srcIP == "?" || srcIP == "-" {
		srcIP = ""
	}
	res := strings.ToLower(firstMapStringStr(kv, "res"))
	cmdLine := firstMapStringStr(kv, "proctitle", "cmd", "a0")
	if cmdLine == "" {
		cmdLine = body
	}

	sev := schema.SeverityInfo
	cat := "host"
	action := strings.ToLower(recType)
	outcome := "observed"
	if res == "failed" || res == "fail" {
		outcome = "failure"
		sev = schema.SeverityMedium
	} else if res == "success" {
		outcome = "success"
	}

	switch strings.ToUpper(recType) {
	case "USER_LOGIN", "USER_AUTH":
		cat = "auth"
		action = "login"
		if outcome == "failure" {
			sev = schema.SeverityMedium
		}
	case "ADD_USER", "DEL_USER", "ADD_GROUP", "USER_MGMT", "USER_ROLE_CHANGE":
		cat = "privilege"
		action = "account_change"
		sev = schema.SeverityHigh
	case "EXECVE", "SYSCALL":
		cat = "process"
		action = "exec"
		if reSusExec.MatchString(cmdLine) || reSusExec.MatchString(body) {
			sev = schema.SeverityHigh
		}
	}
	if reTamper.MatchString(body) || reTamper.MatchString(cmdLine) {
		cat = "ops"
		action = "log_tamper"
		sev = maxSeverity(sev, schema.SeverityHigh)
	}

	return schema.Event{
		ID:           deterministicEventID(FormatAuditd, epochStr, seqStr, recType, host),
		Timestamp:    ts,
		SourceFormat: FormatAuditd,
		Layer:        "host-hardening",
		Tool:         "auditd",
		Severity:     sev,
		Category:     cat,
		Action:       action,
		Outcome:      outcome,
		SrcIP:        srcIP,
		Host:         host,
		User:         user,
		Process:      proc,
		Path:         firstMapStringStr(kv, "exe", "name", "cwd"),
		Message:      fmt.Sprintf("auditd %s: %s", recType, strings.TrimSpace(cmdLine)),
		Raw:          line,
		Metadata: map[string]any{
			"record_type":  recType,
			"command_line": cmdLine,
			"audit_seq":    seqStr,
		},
	}, true
}

func cloudTrailMapToEvent(raw map[string]any, line, sourceName string) (schema.Event, bool) {
	evName := firstMapString(raw, "eventName")
	evSource := firstMapString(raw, "eventSource")
	if evName == "" && evSource == "" {
		return schema.Event{}, false
	}

	ts := parseFlexibleTime(firstMapString(raw, "eventTime", "timestamp"), time.Now().UTC().Year())
	srcIP := firstMapString(raw, "sourceIPAddress")
	if strings.Contains(srcIP, ".amazonaws.com") {
		srcIP = ""
	}

	user := ""
	if ui, ok := raw["userIdentity"].(map[string]any); ok {
		user = firstMapString(ui, "userName", "arn", "principalId", "type")
	}
	region := firstMapString(raw, "awsRegion")
	errCode := firstMapString(raw, "errorCode")
	readOnly := false
	if b, ok := raw["readOnly"].(bool); ok {
		readOnly = b
	}

	sev := schema.SeverityInfo
	cat := "cloud"
	action := evName
	outcome := "success"
	if errCode != "" {
		outcome = "failure"
		if strings.Contains(strings.ToLower(errCode), "denied") || strings.Contains(strings.ToLower(errCode), "unauthorized") {
			sev = schema.SeverityMedium
		}
	}

	lowerName := strings.ToLower(evName)
	switch lowerName {
	case "stoplogging", "deletetrail", "updatetrail", "deleteflowlogs":
		cat = "ops"
		action = "log_tamper"
		sev = schema.SeverityCritical
	case "consolelogin":
		cat = "auth"
		action = "login"
		if respMap, ok := raw["responseElements"].(map[string]any); ok {
			if strings.EqualFold(firstMapString(respMap, "ConsoleLogin"), "Failure") {
				outcome = "failure"
				sev = schema.SeverityMedium
			}
		}
		if errCode != "" {
			outcome = "failure"
			sev = schema.SeverityMedium
		}
	case "createaccesskey", "createuser", "attachuserpolicy", "attachrolepolicy", "putuserpolicy", "assumerole":
		cat = "privilege"
		action = "account_change"
		sev = schema.SeverityHigh
	default:
		if !readOnly && sev == schema.SeverityInfo {
			sev = schema.SeverityLow
		}
	}

	evID := firstMapString(raw, "eventID", "requestID")
	if evID == "" {
		evID = deterministicEventID(FormatCloudTrail, evSource, evName, user, ts.String())
	}
	host := "aws:" + defaultString(region, "global")
	meta := map[string]any{
		"event_name":   evName,
		"event_source": evSource,
		"aws_region":   region,
	}
	if errCode != "" {
		meta["error_code"] = errCode
	}
	if sourceName != "" {
		meta["source_name"] = sourceName
	}

	return schema.Event{
		ID:           evID,
		Timestamp:    ts,
		SourceFormat: FormatCloudTrail,
		Layer:        "cloud-audit",
		Tool:         "aws-cloudtrail",
		RuleID:       evName,
		Severity:     sev,
		Category:     cat,
		Action:       action,
		Outcome:      outcome,
		SrcIP:        srcIP,
		Host:         host,
		User:         user,
		Message:      fmt.Sprintf("CloudTrail %s/%s user=%s outcome=%s", evSource, evName, defaultString(user, "unknown"), outcome),
		Raw:          line,
		Metadata:     meta,
	}, true
}

func k8sAuditMapToEvent(raw map[string]any, line string) (schema.Event, bool) {
	verb := strings.ToLower(firstMapString(raw, "verb"))
	reqURI := firstMapString(raw, "requestURI")
	if verb == "" && reqURI == "" {
		return schema.Event{}, false
	}

	ts := parseFlexibleTime(firstMapString(raw, "requestReceivedTimestamp", "stageTimestamp", "timestamp"), time.Now().UTC().Year())
	var user string
	if uMap, ok := raw["user"].(map[string]any); ok {
		user = firstMapString(uMap, "username", "uid")
	}
	var srcIP string
	if arr, ok := raw["sourceIPs"].([]any); ok && len(arr) > 0 {
		srcIP = strings.TrimSpace(fmt.Sprintf("%v", arr[0]))
	}
	var resource, subresource, ns, name string
	if obj, ok := raw["objectRef"].(map[string]any); ok {
		resource = firstMapString(obj, "resource")
		subresource = firstMapString(obj, "subresource")
		ns = firstMapString(obj, "namespace")
		name = firstMapString(obj, "name")
	}
	var status int
	if rs, ok := raw["responseStatus"].(map[string]any); ok {
		status = firstMapInt(rs, "code")
	}

	sev := schema.SeverityInfo
	cat := "k8s"
	action := verb
	outcome := "success"
	if status >= 400 {
		outcome = "failure"
		if status == 401 || status == 403 {
			sev = schema.SeverityMedium
		}
	}
	fullRes := resource
	if subresource != "" {
		fullRes += "/" + subresource
	}
	if fullRes == "pods/exec" || fullRes == "pods/attach" || resource == "clusterrolebindings" || resource == "secrets" {
		sev = maxSeverity(sev, schema.SeverityHigh)
		if resource == "clusterrolebindings" {
			cat = "privilege"
		}
	}
	if status == 403 && strings.Contains(strings.ToLower(reqURI), "secret") {
		sev = maxSeverity(sev, schema.SeverityHigh)
	}

	evID := firstMapString(raw, "auditID")
	if evID == "" {
		evID = deterministicEventID(FormatK8sAudit, verb, reqURI, user, ts.String())
	}
	host := "k8s-apiserver"
	if ns != "" {
		host = "k8s:" + ns
	}

	return schema.Event{
		ID:           evID,
		Timestamp:    ts,
		SourceFormat: FormatK8sAudit,
		Layer:        "cloud-audit",
		Tool:         "kubernetes-audit",
		Severity:     sev,
		Category:     cat,
		Action:       action,
		Outcome:      outcome,
		SrcIP:        srcIP,
		Host:         host,
		User:         user,
		Path:         fullRes,
		HTTPMethod:   strings.ToUpper(verb),
		HTTPPath:     reqURI,
		HTTPStatus:   status,
		Message:      fmt.Sprintf("k8s audit %s %s ns=%s status=%d", verb, defaultString(fullRes, reqURI), defaultString(ns, "cluster"), status),
		Raw:          line,
		Metadata: map[string]any{
			"k8s_verb":      verb,
			"k8s_resource":  fullRes,
			"k8s_namespace": ns,
			"k8s_name":      name,
		},
	}, true
}

func suricataMapToEvent(raw map[string]any, line string) (schema.Event, bool) {
	evType := strings.ToLower(firstMapString(raw, "event_type"))
	if evType == "" {
		return schema.Event{}, false
	}
	ts := parseFlexibleTime(firstMapString(raw, "timestamp"), time.Now().UTC().Year())
	srcIP := firstMapString(raw, "src_ip")
	dstIP := firstMapString(raw, "dest_ip")
	dstPort := firstMapInt(raw, "dest_port")
	host := firstMapString(raw, "host", "sensor")
	proto := firstMapString(raw, "proto")

	sev := schema.SeverityInfo
	cat := "network"
	action := evType
	outcome := "observed"
	var ruleID, msg, httpMethod, httpPath, domain string
	var httpStatus int

	if alertMap, ok := raw["alert"].(map[string]any); ok {
		cat = "network"
		action = defaultString(firstMapString(alertMap, "action"), "alert")
		outcome = "alert"
		ruleID = firstMapString(alertMap, "signature_id")
		msg = firstMapString(alertMap, "signature")
		switch firstMapInt(alertMap, "severity") {
		case 1:
			sev = schema.SeverityCritical
		case 2:
			sev = schema.SeverityHigh
		case 3:
			sev = schema.SeverityMedium
		default:
			sev = schema.SeverityLow
		}
	}
	if dnsMap, ok := raw["dns"].(map[string]any); ok {
		domain = firstMapString(dnsMap, "rrname")
		if msg == "" && domain != "" {
			msg = "DNS query: " + domain
		}
	}
	if httpMap, ok := raw["http"].(map[string]any); ok {
		httpMethod = firstMapString(httpMap, "http_method")
		httpPath = firstMapString(httpMap, "url")
		httpStatus = firstMapInt(httpMap, "status")
		if domain == "" {
			domain = firstMapString(httpMap, "hostname")
		}
		if reWebProbe.MatchString(httpPath) {
			sev = maxSeverity(sev, schema.SeverityHigh)
			action = "probe"
		}
	}
	if msg == "" {
		msg = fmt.Sprintf("Suricata %s proto=%s dst=%s:%d", evType, proto, dstIP, dstPort)
	}

	meta := map[string]any{
		"event_type": evType,
		"proto":      proto,
	}
	if domain != "" {
		meta["domain"] = domain
	}

	return schema.Event{
		ID:           deterministicEventID(FormatSuricata, evType, srcIP, dstIP, ruleID, ts.String()),
		Timestamp:    ts,
		SourceFormat: FormatSuricata,
		Layer:        "network-defense",
		Tool:         "suricata",
		RuleID:       ruleID,
		Severity:     sev,
		Category:     cat,
		Action:       action,
		Outcome:      outcome,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Host:         host,
		HTTPMethod:   httpMethod,
		HTTPPath:     httpPath,
		HTTPStatus:   httpStatus,
		Message:      msg,
		Raw:          line,
		Metadata:     meta,
	}, true
}

func winEVTXMapToEvent(raw map[string]any, line string) (schema.Event, bool) {
	evID := firstMapInt(raw, "EventID", "event_id")
	if evID <= 0 {
		return schema.Event{}, false
	}
	evData, _ := raw["EventData"].(map[string]any)
	lookup := func(keys ...string) string {
		if v := firstMapString(raw, keys...); v != "" {
			return v
		}
		if evData != nil {
			return firstMapString(evData, keys...)
		}
		return ""
	}

	ts := parseFlexibleTime(firstMapString(raw, "TimeCreated", "timestamp", "@timestamp"), time.Now().UTC().Year())
	host := lookup("Computer", "Hostname", "host")
	user := lookup("TargetUserName", "SubjectUserName", "User", "user")
	srcIP := lookup("IpAddress", "SourceIp", "src_ip")
	if srcIP == "-" || srcIP == "::1" {
		srcIP = ""
	}
	proc := lookup("Image", "NewProcessName", "ProcessName", "process")
	cmdLine := lookup("CommandLine", "ParentCommandLine")

	sev := schema.SeverityInfo
	cat := "host"
	action := fmt.Sprintf("event_%d", evID)
	outcome := "observed"
	switch evID {
	case 4625:
		cat = "auth"
		action = "login"
		outcome = "failure"
		sev = schema.SeverityMedium
	case 4624:
		cat = "auth"
		action = "login"
		outcome = "success"
	case 4720, 4728, 4732, 4756:
		cat = "privilege"
		action = "account_change"
		outcome = "success"
		sev = schema.SeverityHigh
	case 4672:
		cat = "privilege"
		action = "special_privileges"
		outcome = "success"
		sev = schema.SeverityMedium
	case 4688, 1:
		cat = "process"
		action = "exec"
		if reSusExec.MatchString(cmdLine) {
			sev = schema.SeverityHigh
		}
	case 1102, 104:
		cat = "ops"
		action = "log_tamper"
		sev = schema.SeverityCritical
	}

	msg := firstMapString(raw, "Message", "message")
	if msg == "" {
		msg = fmt.Sprintf("WinEvent %d user=%s cmd=%s", evID, defaultString(user, "system"), cmdLine)
	}

	return schema.Event{
		ID:           deterministicEventID(FormatWinEVTX, strconv.Itoa(evID), host, user, cmdLine, ts.String()),
		Timestamp:    ts,
		SourceFormat: FormatWinEVTX,
		Layer:        "host-hardening",
		Tool:         "windows-evtx",
		RuleID:       strconv.Itoa(evID),
		Severity:     sev,
		Category:     cat,
		Action:       action,
		Outcome:      outcome,
		SrcIP:        srcIP,
		Host:         host,
		User:         user,
		Process:      proc,
		Message:      strings.TrimSpace(msg),
		Raw:          line,
		Metadata: map[string]any{
			"event_id":     strconv.Itoa(evID),
			"command_line": cmdLine,
			"channel":      firstMapString(raw, "Channel", "channel"),
		},
	}, true
}

func parseLEEFLine(line string) (schema.Event, bool) {
	idx := strings.Index(line, "LEEF:")
	if idx < 0 {
		return schema.Event{}, false
	}
	leefBody := line[idx:]
	parts := strings.SplitN(leefBody, "|", 6)
	if len(parts) < 6 {
		return schema.Event{}, false
	}
	headerVer := strings.TrimPrefix(parts[0], "LEEF:")
	vendor, product, eventID, rest := parts[1], parts[2], parts[4], parts[5]

	sep := "\t"
	kvRaw := rest
	if strings.HasPrefix(headerVer, "2.") {
		sub := strings.SplitN(rest, "|", 2)
		if len(sub) == 2 {
			customSep := sub[0]
			if strings.HasPrefix(customSep, "0x") {
				if code, err := strconv.ParseInt(customSep[2:], 16, 32); err == nil && code > 0 {
					sep = string(rune(code))
				}
			} else if customSep != "" {
				sep = customSep
			}
			kvRaw = sub[1]
		}
	}

	kv := make(map[string]string)
	tokens := strings.Split(kvRaw, sep)
	if len(tokens) == 1 && sep == "\t" {
		tokens = strings.Fields(kvRaw)
	}
	for _, tok := range tokens {
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			kv[strings.TrimSpace(tok[:eq])] = strings.TrimSpace(tok[eq+1:])
		}
	}

	dstPort, _ := strconv.Atoi(firstMapStringStr(kv, "dstPort"))
	sev := mapCEFSeverity(firstMapStringStr(kv, "sev", "severity"))
	msg := firstMapStringStr(kv, "msg", "reason", "cat")
	if msg == "" {
		msg = eventID
	}
	srcIP := firstMapStringStr(kv, "src", "srcIP")
	host := firstMapStringStr(kv, "devName", "identHostName", "dhost")
	user := firstMapStringStr(kv, "usrName", "srcUser", "suser")
	ts := parseFlexibleTime(firstMapStringStr(kv, "devTime", "timestamp"), time.Now().UTC().Year())

	return schema.Event{
		ID:           deterministicEventID(FormatLEEF, vendor, product, eventID, srcIP, msg),
		Timestamp:    ts,
		SourceFormat: FormatLEEF,
		Layer:        inferLayerFromTool(product),
		Tool:         product,
		RuleID:       eventID,
		Severity:     sev,
		Category:     defaultString(strings.ToLower(firstMapStringStr(kv, "cat")), "leef"),
		Action:       defaultString(strings.ToLower(firstMapStringStr(kv, "action")), "alert"),
		Outcome:      defaultString(strings.ToLower(firstMapStringStr(kv, "outcome")), "alert"),
		SrcIP:        srcIP,
		DstIP:        firstMapStringStr(kv, "dst", "dstIP"),
		DstPort:      dstPort,
		Host:         host,
		User:         user,
		Message:      msg,
		Raw:          line,
		Metadata: map[string]any{
			"leef_vendor":  vendor,
			"leef_product": product,
			"leef_event":   eventID,
		},
	}, true
}
