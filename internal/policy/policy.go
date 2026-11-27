package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

// Policy configures thresholds, watchlists, fail-closed waivers, custom rules, and alert routes.
type Policy struct {
	MinSeverity         schema.Severity `yaml:"min_severity" json:"min_severity"`
	SuppressionWindow   string          `yaml:"suppression_window" json:"suppression_window"`
	AuthBurstThreshold  int             `yaml:"auth_burst_threshold" json:"auth_burst_threshold"`
	WebProbeThreshold   int             `yaml:"web_probe_threshold" json:"web_probe_threshold"`
	AlertStormThreshold int             `yaml:"alert_storm_threshold" json:"alert_storm_threshold"`
	WatchedIPs          []string        `yaml:"watched_ips" json:"watched_ips"`
	WatchedHosts        []string        `yaml:"watched_hosts" json:"watched_hosts"`
	WatchedUsers        []string        `yaml:"watched_users" json:"watched_users"`
	Suppressions        []Suppression   `yaml:"suppressions" json:"suppressions"`
	CustomRules         []CustomRule    `yaml:"custom_rules" json:"custom_rules"`
	Routes              []AlertRoute    `yaml:"routes" json:"routes"`
}

// Suppression represents a time-bounded fail-closed waiver entry.
type Suppression struct {
	RuleID         string `yaml:"rule_id" json:"rule_id"`
	TargetContains string `yaml:"target_contains" json:"target_contains"`
	Reason         string `yaml:"reason" json:"reason"`
	ExpiresOn      string `yaml:"expires_on" json:"expires_on"`
}

// CustomRule defines declarative Detection-as-Code rules in YAML/JSON.
type CustomRule struct {
	ID          string            `yaml:"id" json:"id"`
	Title       string            `yaml:"title" json:"title"`
	Description string            `yaml:"description" json:"description"`
	Severity    schema.Severity   `yaml:"severity" json:"severity"`
	Module      string            `yaml:"module" json:"module"`
	Remediation string            `yaml:"remediation" json:"remediation"`
	MitreD3FEND string            `yaml:"mitre_d3fend" json:"mitre_d3fend"`
	Match       map[string]string `yaml:"match" json:"match"`
	Threshold   int               `yaml:"threshold" json:"threshold"`
	Window      string            `yaml:"window" json:"window"`
	GroupBy     string            `yaml:"group_by" json:"group_by"`

	compiledRegex *regexp.Regexp
	windowDur     time.Duration
}

// AlertRoute configures an incident notification sink.
type AlertRoute struct {
	Name        string          `yaml:"name" json:"name"`
	Type        string          `yaml:"type" json:"type"`
	URL         string          `yaml:"url" json:"url"`
	Path        string          `yaml:"path" json:"path"`
	MinSeverity schema.Severity `yaml:"min_severity" json:"min_severity"`
	SecretEnv   string          `yaml:"secret_env" json:"secret_env"`
	TokenEnv    string          `yaml:"token_env" json:"token_env"`
	ChatID      string          `yaml:"chat_id" json:"chat_id"`
}

// DefaultPolicy returns safe, balanced default thresholds and a 10m alert suppression window.
func DefaultPolicy() Policy {
	return Policy{
		MinSeverity:         schema.SeverityInfo,
		SuppressionWindow:   "10m",
		AuthBurstThreshold:  5,
		WebProbeThreshold:   5,
		AlertStormThreshold: 10,
	}
}

// DiscoverPolicy locates an explicit policy file or auto-discovers .raksa-siem.{yml,yaml,json}.
func DiscoverPolicy(targetPath, explicitPath string) (Policy, string, error) {
	if strings.TrimSpace(explicitPath) != "" {
		pol, err := LoadPolicy(explicitPath)
		return pol, explicitPath, err
	}
	base := targetPath
	if info, err := os.Stat(targetPath); err == nil && !info.IsDir() {
		base = filepath.Dir(targetPath)
	} else if err != nil || strings.TrimSpace(base) == "" {
		base = "."
	}
	for _, candidate := range []string{".raksa-siem.yml", ".raksa-siem.yaml", ".raksa-siem.json"} {
		full := filepath.Join(base, candidate)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			pol, err := LoadPolicy(full)
			return pol, full, err
		}
	}
	return DefaultPolicy(), "", nil
}

// LoadPolicy parses and strictly validates a YAML or JSON SIEM policy file.
func LoadPolicy(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy %s: %w", path, err)
	}
	pol := DefaultPolicy()
	if err := yaml.Unmarshal(raw, &pol); err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	if err := pol.ValidateAndCompile(); err != nil {
		return Policy{}, fmt.Errorf("invalid policy %s: %w", path, err)
	}
	return pol, nil
}

// ValidateAndCompile checks fail-closed waiver constraints, severities, regexes, and route sinks.
func (p *Policy) ValidateAndCompile() error {
	if p.SuppressionWindow == "" {
		p.SuppressionWindow = "10m"
	}
	if d, err := time.ParseDuration(p.SuppressionWindow); err != nil || d <= 0 {
		return fmt.Errorf("invalid suppression_window %q: must be positive Go duration (e.g. 10m)", p.SuppressionWindow)
	}
	if p.AuthBurstThreshold <= 0 {
		p.AuthBurstThreshold = 5
	}
	if p.WebProbeThreshold <= 0 {
		p.WebProbeThreshold = 5
	}
	if p.AlertStormThreshold <= 0 {
		p.AlertStormThreshold = 10
	}
	if p.MinSeverity != "" {
		sev, err := schema.ParseSeverity(string(p.MinSeverity))
		if err != nil {
			return err
		}
		p.MinSeverity = sev
	} else {
		p.MinSeverity = schema.SeverityInfo
	}

	today := time.Now().UTC().Format("2006-01-02")
	for idx, sup := range p.Suppressions {
		if strings.TrimSpace(sup.RuleID) == "" {
			return fmt.Errorf("suppressions[%d]: rule_id is required", idx)
		}
		if strings.TrimSpace(sup.Reason) == "" {
			return fmt.Errorf("suppressions[%d] (%s): fail-closed policy requires non-empty reason", idx, sup.RuleID)
		}
		exp := strings.TrimSpace(sup.ExpiresOn)
		if _, err := time.Parse("2006-01-02", exp); err != nil {
			return fmt.Errorf("suppressions[%d] (%s): expires_on must be YYYY-MM-DD", idx, sup.RuleID)
		}
		if exp < today {
			return fmt.Errorf("suppressions[%d] (%s): waiver expired on %s", idx, sup.RuleID, exp)
		}
	}

	for idx := range p.CustomRules {
		cr := &p.CustomRules[idx]
		if strings.TrimSpace(cr.ID) == "" || strings.TrimSpace(cr.Title) == "" {
			return fmt.Errorf("custom_rules[%d]: id and title are required", idx)
		}
		if len(cr.Match) == 0 {
			return fmt.Errorf("custom_rules[%d] (%s): match map cannot be empty", idx, cr.ID)
		}
		if cr.Severity == "" {
			cr.Severity = schema.SeverityHigh
		} else {
			sev, err := schema.ParseSeverity(string(cr.Severity))
			if err != nil {
				return fmt.Errorf("custom_rules[%d] (%s): %w", idx, cr.ID, err)
			}
			cr.Severity = sev
		}
		if cr.Module == "" {
			cr.Module = "custom"
		}
		if cr.MitreD3FEND == "" {
			cr.MitreD3FEND = "D3-SCA"
		}
		if cr.Window == "" {
			cr.Window = "5m"
		}
		dur, err := time.ParseDuration(cr.Window)
		if err != nil || dur <= 0 {
			return fmt.Errorf("custom_rules[%d] (%s): invalid window %q", idx, cr.ID, cr.Window)
		}
		cr.windowDur = dur
		if cr.GroupBy == "" {
			cr.GroupBy = "src_ip"
		}
		if rx := strings.TrimSpace(cr.Match["message_regex"]); rx != "" {
			compiled, err := regexp.Compile(rx)
			if err != nil {
				return fmt.Errorf("custom_rules[%d] (%s): invalid message_regex: %w", idx, cr.ID, err)
			}
			cr.compiledRegex = compiled
		}
	}

	for idx := range p.Routes {
		rt := &p.Routes[idx]
		kind := strings.ToLower(strings.TrimSpace(rt.Type))
		if !slices.Contains([]string{"webhook", "slack", "discord", "telegram", "file"}, kind) {
			return fmt.Errorf("routes[%d]: unsupported route type %q", idx, rt.Type)
		}
		rt.Type = kind
		if kind == "file" {
			if strings.TrimSpace(rt.Path) == "" {
				return fmt.Errorf("routes[%d] (file): path is required", idx)
			}
		} else if err := ValidateHTTPSOrLocalhostURL(rt.URL); err != nil {
			return fmt.Errorf("routes[%d] (%s): %w", idx, kind, err)
		}
		if rt.MinSeverity == "" {
			rt.MinSeverity = schema.SeverityMedium
		} else {
			sev, err := schema.ParseSeverity(string(rt.MinSeverity))
			if err != nil {
				return fmt.Errorf("routes[%d]: %w", idx, err)
			}
			rt.MinSeverity = sev
		}
	}
	return nil
}

// ValidateHTTPSOrLocalhostURL rejects cleartext HTTP endpoints except loopback hosts used in local testing.
func ValidateHTTPSOrLocalhostURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("malformed url %q: %w", raw, err)
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" && host != "" {
		return nil
	}
	if u.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return nil
	}
	return fmt.Errorf("unsafe alert sink URL %q: HTTPS required (localhost HTTP permitted only for testing)", raw)
}

// SuppressionDuration parses p.SuppressionWindow safely.
func (p Policy) SuppressionDuration() time.Duration {
	if d, err := time.ParseDuration(p.SuppressionWindow); err == nil && d > 0 {
		return d
	}
	return 10 * time.Minute
}

// WindowDuration returns the validated aggregation window for CustomRule.
func (c CustomRule) WindowDuration() time.Duration {
	if c.windowDur > 0 {
		return c.windowDur
	}
	if d, err := time.ParseDuration(c.Window); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
}

// MatchesEvent tests all predicates configured on CustomRule against ev.
func (c CustomRule) MatchesEvent(ev schema.Event) bool {
	for k, expected := range c.Match {
		expLow := strings.ToLower(strings.TrimSpace(expected))
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "layer":
			if strings.ToLower(ev.Layer) != expLow {
				return false
			}
		case "category":
			if strings.ToLower(ev.Category) != expLow {
				return false
			}
		case "action":
			if strings.ToLower(ev.Action) != expLow {
				return false
			}
		case "outcome":
			if strings.ToLower(ev.Outcome) != expLow {
				return false
			}
		case "severity":
			if strings.ToLower(string(ev.Severity)) != expLow {
				return false
			}
		case "src_ip":
			if ev.SrcIP != strings.TrimSpace(expected) {
				return false
			}
		case "dst_ip":
			if ev.DstIP != strings.TrimSpace(expected) {
				return false
			}
		case "host":
			if !strings.EqualFold(ev.Host, strings.TrimSpace(expected)) {
				return false
			}
		case "user":
			if !strings.EqualFold(ev.User, strings.TrimSpace(expected)) {
				return false
			}
		case "process":
			if !strings.Contains(strings.ToLower(ev.Process), expLow) {
				return false
			}
		case "rule_id":
			if !strings.EqualFold(ev.RuleID, strings.TrimSpace(expected)) {
				return false
			}
		case "tool":
			if !strings.EqualFold(ev.Tool, strings.TrimSpace(expected)) {
				return false
			}
		case "http_method":
			if !strings.EqualFold(ev.HTTPMethod, strings.TrimSpace(expected)) {
				return false
			}
		case "http_status":
			if fmt.Sprintf("%d", ev.HTTPStatus) != strings.TrimSpace(expected) {
				return false
			}
		case "contains", "message_contains":
			hay := strings.ToLower(ev.Message + " " + ev.HTTPPath + " " + ev.Path + " " + ev.Raw)
			if !strings.Contains(hay, expLow) {
				return false
			}
		case "message_regex":
			if c.compiledRegex == nil {
				rx, err := regexp.Compile(expected)
				if err != nil || !rx.MatchString(ev.Message+" "+ev.Raw) {
					return false
				}
			} else if !c.compiledRegex.MatchString(ev.Message + " " + ev.Raw) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ApplyPolicy filters findings by min_severity and active non-expired suppressions.
func ApplyPolicy(findings []schema.Finding, pol Policy) ([]schema.Finding, int) {
	kept := make([]schema.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if pol.MinSeverity != "" && !f.Severity.MeetsThreshold(pol.MinSeverity) {
			suppressed++
			continue
		}
		if isSuppressed(f, pol.Suppressions) {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

func isSuppressed(f schema.Finding, sups []Suppression) bool {
	for _, s := range sups {
		if !strings.EqualFold(strings.TrimSpace(s.RuleID), f.RuleID) {
			continue
		}
		if s.TargetContains == "" || strings.Contains(strings.ToLower(f.Target), strings.ToLower(s.TargetContains)) {
			return true
		}
	}
	return false
}

// FindingFingerprint returns a deterministic SHA-256 fingerprint for baseline tracking.
func FindingFingerprint(f schema.Finding) string {
	h := sha256.Sum256([]byte(f.RuleID + "\x00" + f.Target + "\x00" + f.ID))
	return hex.EncodeToString(h[:])[:24]
}

// BaselineFile stores suppressed finding fingerprints on disk.
type BaselineFile struct {
	SchemaVersion string   `json:"schema_version"`
	Tool          string   `json:"tool"`
	Fingerprints  []string `json:"fingerprints"`
}

// WriteBaseline persists finding fingerprints deterministically.
func WriteBaseline(path string, findings []schema.Finding) error {
	fpSet := make(map[string]bool, len(findings))
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		fp := FindingFingerprint(f)
		if !fpSet[fp] {
			fpSet[fp] = true
			fps = append(fps, fp)
		}
	}
	slices.Sort(fps)
	doc := BaselineFile{
		SchemaVersion: schema.SchemaVersion,
		Tool:          schema.ToolName,
		Fingerprints:  fps,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create baseline directory: %w", err)
		}
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LoadBaseline loads suppressed finding fingerprints cleanly.
func LoadBaseline(path string) (map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var doc BaselineFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	out := make(map[string]bool, len(doc.Fingerprints))
	for _, fp := range doc.Fingerprints {
		if strings.TrimSpace(fp) != "" {
			out[strings.TrimSpace(fp)] = true
		}
	}
	return out, nil
}

// ApplyBaseline removes baseline-acknowledged findings cleanly.
func ApplyBaseline(findings []schema.Finding, base map[string]bool) ([]schema.Finding, int) {
	if len(base) == 0 {
		return findings, 0
	}
	kept := make([]schema.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if base[FindingFingerprint(f)] {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}
