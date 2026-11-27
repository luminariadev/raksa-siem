package schema

import (
	"fmt"
	"strings"
	"time"
)

const (
	SchemaVersion = "1.0"
	ToolName      = "raksa-siem"
	LayerName     = "siem"
)

// Version can be overridden at build time via -ldflags "-X github.com/luminariadev/raksa-siem/internal/schema.Version=0.3.0".
var Version = "0.3.0"

// Severity represents Raksa Schema v1 normalized alert severity levels.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ParseSeverity normalizes a textual severity string into a validated Severity value.
func ParseSeverity(raw string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "info":
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity %q: expected critical, high, medium, low, or info", raw)
	}
}

// Rank returns numeric severity ordering from 1 (info) to 5 (critical).
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// MeetsThreshold reports whether s meets or exceeds threshold.
func (s Severity) MeetsThreshold(threshold Severity) bool {
	if threshold == "" {
		return false
	}
	return s.Rank() >= threshold.Rank()
}

// Finding follows Raksa Finding Schema v1 shared across Layers 1 through 6.
type Finding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Module      string         `json:"module"`
	Layer       string         `json:"layer"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Target      string         `json:"target"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation"`
	MitreD3FEND string         `json:"mitre_d3fend"`
	Timestamp   time.Time      `json:"timestamp"`
}

// Summary counts findings by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// PostureScore summarizes security posture on a deterministic 0-100 scale.
type PostureScore struct {
	Score int    `json:"score"`
	Grade string `json:"grade"`
}

// Report is the top-level Raksa Schema v1 report envelope.
type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          string        `json:"tool"`
	Layer         string        `json:"layer"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Posture       *PostureScore `json:"posture,omitempty"`
	Summary       Summary       `json:"summary"`
	Findings      []Finding     `json:"findings"`
}

// RuleInfo describes a cataloged built-in SIEM correlation or detection rule.
type RuleInfo struct {
	RuleID         string   `json:"rule_id"`
	Title          string   `json:"title"`
	Module         string   `json:"module"`
	Severity       Severity `json:"severity"`
	Standard       string   `json:"standard"`
	MitreD3FEND    string   `json:"mitre_d3fend"`
	MitreTechnique string   `json:"mitre_technique"`
	Description    string   `json:"description"`
}

// Event is the canonical normalized telemetry event shared across log parsers and Raksa layer reports.
type Event struct {
	ID           string         `json:"id"`
	Timestamp    time.Time      `json:"timestamp"`
	SourceFormat string         `json:"source_format"`
	Layer        string         `json:"layer"`
	Tool         string         `json:"tool,omitempty"`
	RuleID       string         `json:"rule_id,omitempty"`
	Severity     Severity       `json:"severity"`
	Category     string         `json:"category"`
	Action       string         `json:"action"`
	Outcome      string         `json:"outcome"`
	SrcIP        string         `json:"src_ip,omitempty"`
	DstIP        string         `json:"dst_ip,omitempty"`
	DstPort      int            `json:"dst_port,omitempty"`
	Host         string         `json:"host,omitempty"`
	User         string         `json:"user,omitempty"`
	Process      string         `json:"process,omitempty"`
	Path         string         `json:"path,omitempty"`
	HTTPMethod   string         `json:"http_method,omitempty"`
	HTTPPath     string         `json:"http_path,omitempty"`
	HTTPStatus   int            `json:"http_status,omitempty"`
	Message      string         `json:"message"`
	Raw          string         `json:"raw,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// ComputePosture calculates deterministic posture score (0-100) and letter grade (A+..F).
func ComputePosture(findings []Finding) *PostureScore {
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			score -= 30
		case SeverityHigh:
			score -= 18
		case SeverityMedium:
			score -= 8
		case SeverityLow:
			score -= 3
		case SeverityInfo:
		}
	}
	if score < 0 {
		score = 0
	}

	grade := "F"
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 55:
		grade = "D"
	}
	return &PostureScore{Score: score, Grade: grade}
}

// SummarizeFindings counts findings per severity level.
func SummarizeFindings(findings []Finding) Summary {
	var s Summary
	s.Total = len(findings)
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

// NewReport builds a populated Raksa Schema v1 Report envelope.
func NewReport(findings []Finding) Report {
	copied := make([]Finding, len(findings))
	copy(copied, findings)
	for i := range copied {
		if copied[i].Layer == "" {
			copied[i].Layer = LayerName
		}
		if copied[i].Timestamp.IsZero() {
			copied[i].Timestamp = time.Now().UTC()
		}
	}
	return Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolName,
		Layer:         LayerName,
		GeneratedAt:   time.Now().UTC(),
		Posture:       ComputePosture(copied),
		Summary:       SummarizeFindings(copied),
		Findings:      copied,
	}
}

// RuleCatalog returns built-in SIEM-* correlation and detection rules, optionally filtered by module.
func RuleCatalog(moduleFilter ...string) []RuleInfo {
	mod := ""
	if len(moduleFilter) > 0 {
		mod = strings.ToLower(strings.TrimSpace(moduleFilter[0]))
	}
	if mod == "" {
		out := make([]RuleInfo, len(builtInRules))
		copy(out, builtInRules)
		return out
	}
	var out []RuleInfo
	for _, r := range builtInRules {
		if strings.ToLower(r.Module) == mod {
			out = append(out, r)
		}
	}
	return out
}

// LookupRule finds built-in metadata by rule_id.
func LookupRule(ruleID string) (RuleInfo, bool) {
	for _, r := range builtInRules {
		if r.RuleID == ruleID {
			return r, true
		}
	}
	return RuleInfo{}, false
}

var builtInRules = []RuleInfo{
	{
		RuleID:         "SIEM-001",
		Title:          "SSH or authentication brute-force burst detected",
		Module:         "auth",
		Severity:       SeverityHigh,
		Standard:       "MITRE ATT&CK T1110.001",
		MitreD3FEND:    "D3-UAL",
		MitreTechnique: "User Account Lockout / Auth Log Analysis",
		Description:    "Single source IP generated repeated failed authentication attempts inside the sliding correlation window.",
	},
	{
		RuleID:         "SIEM-002",
		Title:          "Authentication brute-force followed by successful login",
		Module:         "auth",
		Severity:       SeverityCritical,
		Standard:       "MITRE ATT&CK T1110 / T1078",
		MitreD3FEND:    "D3-UAL",
		MitreTechnique: "Valid Account Compromise Detection",
		Description:    "Source IP with repeated authentication failures subsequently achieved an accepted login session.",
	},
	{
		RuleID:         "SIEM-003",
		Title:          "Password spraying across accounts or distributed source IPs",
		Module:         "auth",
		Severity:       SeverityHigh,
		Standard:       "MITRE ATT&CK T1110.003",
		MitreD3FEND:    "D3-ANET",
		MitreTechnique: "Authentication Spray Correlation",
		Description:    "Single source targeted multiple distinct usernames, or a single account received failures across multiple distinct IPs.",
	},
	{
		RuleID:         "SIEM-004",
		Title:          "Suspicious privilege escalation or persistence command logged",
		Module:         "auth",
		Severity:       SeverityHigh,
		Standard:       "MITRE ATT&CK T1548 / T1136",
		MitreD3FEND:    "D3-PSA",
		MitreTechnique: "Privilege Escalation Process Inspection",
		Description:    "Authentication telemetry captured high-risk privilege escalation, failed sudo abuse, root escalation shell, or local account creation.",
	},
	{
		RuleID:         "SIEM-005",
		Title:          "Rapid multi-IP login anomaly for single user",
		Module:         "auth",
		Severity:       SeverityMedium,
		Standard:       "MITRE ATT&CK T1078",
		MitreD3FEND:    "D3-UBA",
		MitreTechnique: "Multi-Source Session Anomaly",
		Description:    "Single account authenticated from distinct external source IPs within a tight correlation window.",
	},
	{
		RuleID:         "SIEM-101",
		Title:          "Web 401/403/404 enumeration spike from single source",
		Module:         "web-net",
		Severity:       SeverityMedium,
		Standard:       "OWASP API / MITRE T1595",
		MitreD3FEND:    "D3-NTA",
		MitreTechnique: "Web Access Burst Analysis",
		Description:    "Source IP triggered high-rate HTTP 401/403/404 errors characteristic of directory or credential probing.",
	},
	{
		RuleID:         "SIEM-102",
		Title:          "Repeated web exploitation probes or WAF blocks",
		Module:         "web-net",
		Severity:       SeverityHigh,
		Standard:       "OWASP Top 10 / MITRE T1190",
		MitreD3FEND:    "D3-WAF",
		MitreTechnique: "Application Exploit Attempt Correlation",
		Description:    "Access or WAF telemetry recorded repeated SQLi, XSS, path traversal, or WebShield exploit probe signatures.",
	},
	{
		RuleID:         "SIEM-103",
		Title:          "HTTP 5xx server error or resource exhaustion spike",
		Module:         "web-net",
		Severity:       SeverityHigh,
		Standard:       "MITRE ATT&CK T1499",
		MitreD3FEND:    "D3-NTA",
		MitreTechnique: "Service Availability Anomaly Detection",
		Description:    "Elevated burst of HTTP 5xx server failures indicates upstream instability or endpoint availability attack.",
	},
	{
		RuleID:         "SIEM-104",
		Title:          "Network or firewall repeated scan/block escalation",
		Module:         "web-net",
		Severity:       SeverityMedium,
		Standard:       "MITRE ATT&CK T1046",
		MitreD3FEND:    "D3-NI",
		MitreTechnique: "Network Block Escalation",
		Description:    "Multiple network defense alerts or firewall block events accumulated for the same source IP.",
	},
	{
		RuleID:         "SIEM-201",
		Title:          "Multi-layer attack kill chain from single source IP",
		Module:         "correlation",
		Severity:       SeverityCritical,
		Standard:       "MITRE ATT&CK Cross-Tactic Kill Chain",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Security Event Cross-Layer Correlation",
		Description:    "Distinct security layers or log sources reported malicious activity originating from the same source IP within the kill-chain window.",
	},
	{
		RuleID:         "SIEM-202",
		Title:          "Multi-layer compromise indicators on same host or target",
		Module:         "correlation",
		Severity:       SeverityCritical,
		Standard:       "MITRE ATT&CK Cross-Layer Incident",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Host Cross-Layer Correlation",
		Description:    "Same host or asset accumulated suspicious/alerting events across multiple Raksa security layers within the correlation window.",
	},
	{
		RuleID:         "SIEM-203",
		Title:          "Lateral movement pattern across multiple hosts",
		Module:         "correlation",
		Severity:       SeverityCritical,
		Standard:       "MITRE ATT&CK T1021",
		MitreD3FEND:    "D3-NTA",
		MitreTechnique: "Lateral Movement Graph Analysis",
		Description:    "Single external source IP or user accessed or failed across three or more distinct target hosts.",
	},
	{
		RuleID:         "SIEM-204",
		Title:          "DevSecOps pipeline exposure overlapping with runtime compromise",
		Module:         "correlation",
		Severity:       SeverityHigh,
		Standard:       "SLSA / NIST SSDF / MITRE T1195",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Supply-Chain to Runtime Correlation",
		Description:    "Host or target flagged by PipeGuard CI/CD secret or CVE alerts also received runtime threat events.",
	},
	{
		RuleID:         "SIEM-205",
		Title:          "Active malware detection correlated with C2 or host persistence",
		Module:         "correlation",
		Severity:       SeverityHigh,
		Standard:       "MITRE ATT&CK T1105 / T1547",
		MitreD3FEND:    "D3-FA",
		MitreTechnique: "Malware Execution Chain Correlation",
		Description:    "IOCScan malware indicator co-occurred on a host with HostGuard/NetGuard runtime persistence or C2 activity.",
	},
	{
		RuleID:         "SIEM-206",
		Title:          "Ordered multi-step attack kill-chain sequence correlated",
		Module:         "correlation",
		Severity:       SeverityCritical,
		Standard:       "MITRE ATT&CK Kill Chain / EQL Sequence",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Sequential Attack Chain Correlation",
		Description:    "Grouped telemetry matched an ordered sequence of attack stages inside the configured sliding time window.",
	},
	{
		RuleID:         "SIEM-301",
		Title:          "Upstream critical Raksa sensor finding escalated",
		Module:         "ops",
		Severity:       SeverityCritical,
		Standard:       "Raksa Schema v1 SLA",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Critical Finding Triage Escalation",
		Description:    "An upstream Raksa defensive layer emitted a critical-severity finding requiring immediate SIEM routing.",
	},
	{
		RuleID:         "SIEM-302",
		Title:          "High-volume critical/high alert storm detected",
		Module:         "ops",
		Severity:       SeverityHigh,
		Standard:       "SOC Triage Resilience",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Alert Storm Detection",
		Description:    "Aggregate rate of high and critical findings exceeded the configured burst threshold within the sliding window.",
	},
	{
		RuleID:         "SIEM-303",
		Title:          "Log tampering or audit clearing indicator detected",
		Module:         "ops",
		Severity:       SeverityMedium,
		Standard:       "MITRE ATT&CK T1070",
		MitreD3FEND:    "D3-LAM",
		MitreTechnique: "Log Integrity Monitoring",
		Description:    "Telemetry included indicators of log truncation, audit service stoppage, or shell history clearing.",
	},
	{
		RuleID:         "SIEM-401",
		Title:          "Custom YAML correlation rule matched telemetry event",
		Module:         "custom",
		Severity:       SeverityHigh,
		Standard:       "Enterprise Detection-as-Code",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Custom Rule Pattern Match",
		Description:    "Normalized telemetry matched a user-defined event predicate in .raksa-siem.yml.",
	},
	{
		RuleID:         "SIEM-402",
		Title:          "Custom YAML aggregation threshold rule triggered",
		Module:         "custom",
		Severity:       SeverityHigh,
		Standard:       "Enterprise Detection-as-Code",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Custom Windowed Aggregation",
		Description:    "Grouped telemetry events crossed the custom threshold within the rule time window.",
	},
	{
		RuleID:         "SIEM-403",
		Title:          "Sigma detection rule matched telemetry stream",
		Module:         "custom",
		Severity:       SeverityHigh,
		Standard:       "Sigma Detection Rule",
		MitreD3FEND:    "D3-SCA",
		MitreTechnique: "Sigma Signature Correlation",
		Description:    "Normalized telemetry matched a compiled native Sigma YAML detection or windowed aggregation rule.",
	},
	{
		RuleID:         "SIEM-501",
		Title:          "Enterprise watchlist hit on monitored IP, host, or user",
		Module:         "policy",
		Severity:       SeverityMedium,
		Standard:       "Threat Intel Watchlist",
		MitreD3FEND:    "D3-DA",
		MitreTechnique: "Watchlist Indicator Correlation",
		Description:    "Normalized telemetry referenced an IP address, hostname, or user on the configured policy watchlist.",
	},
	{
		RuleID:         "SIEM-502",
		Title:          "STIX 2.1 or CIDR threat intelligence indicator matched",
		Module:         "policy",
		Severity:       SeverityHigh,
		Standard:       "STIX 2.1 / Threat Intelligence Feed",
		MitreD3FEND:    "D3-DA",
		MitreTechnique: "Threat Feed Indicator Match",
		Description:    "Normalized event matched a malicious IP, CIDR range, domain, hash, or user from an external threat intel feed.",
	},
}
