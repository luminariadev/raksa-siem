package intel

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

// Indicator describes a normalized threat intelligence observable.
type Indicator struct {
	Value       string          `json:"value"`
	Kind        string          `json:"kind"` // ip, cidr, domain, user, hash
	Severity    schema.Severity `json:"severity"`
	Source      string          `json:"source,omitempty"`
	Description string          `json:"description,omitempty"`
}

// Match records a threat feed hit against an ingested Event.
type Match struct {
	Indicator  Indicator `json:"indicator"`
	MatchedOn  string    `json:"matched_on"`
	MatchedVal string    `json:"matched_val"`
}

type cidrRule struct {
	prefix    netip.Prefix
	indicator Indicator
}

// ThreatFeed stores compiled IP, CIDR, domain, user, and hash IOCs loaded from STIX 2.1, CSV, or text lists.
type ThreatFeed struct {
	ips     map[string]Indicator
	cidrs   []cidrRule
	domains map[string]Indicator
	users   map[string]Indicator
	hashes  map[string]Indicator
	count   int
}

// NewThreatFeed creates an empty ThreatFeed.
func NewThreatFeed() *ThreatFeed {
	return &ThreatFeed{
		ips:     make(map[string]Indicator),
		domains: make(map[string]Indicator),
		users:   make(map[string]Indicator),
		hashes:  make(map[string]Indicator),
	}
}

// Count returns total loaded indicators.
func (f *ThreatFeed) Count() int {
	if f == nil {
		return 0
	}
	return f.count
}

var reSTIXPattern = regexp.MustCompile(`(?i)\[([a-z0-9\-:.'_]+)\s*=\s*'([^']+)'\]`)

// LoadFile parses STIX 2.1 JSON bundles, JSON arrays, CSV tables, or plaintext IP/CIDR/domain lists into f.
func (f *ThreatFeed) LoadFile(path string) error {
	clean := filepath.Clean(path)
	raw, err := os.ReadFile(clean)
	if err != nil {
		return fmt.Errorf("read threat intel %q: %w", clean, err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(clean))
	if ext == ".json" || trimmed[0] == '{' || trimmed[0] == '[' {
		return f.loadJSON(trimmed, filepath.Base(clean))
	}
	if ext == ".csv" {
		return f.loadCSV(trimmed, filepath.Base(clean))
	}
	return f.loadPlaintext(trimmed, filepath.Base(clean))
}

func (f *ThreatFeed) loadJSON(data []byte, source string) error {
	if data[0] == '[' {
		var list []Indicator
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("parse threat intel JSON array %s: %w", source, err)
		}
		for _, ind := range list {
			if err := f.AddIndicator(ind); err != nil {
				return err
			}
		}
		return nil
	}

	var bundle struct {
		Type    string `json:"type"`
		Objects []struct {
			Type        string `json:"type"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Pattern     string `json:"pattern"`
			Confidence  int    `json:"confidence"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse STIX 2.1 bundle %s: %w", source, err)
	}
	for _, obj := range bundle.Objects {
		if !strings.EqualFold(obj.Type, "indicator") || obj.Pattern == "" {
			continue
		}
		sev := schema.SeverityHigh
		if obj.Confidence >= 85 {
			sev = schema.SeverityCritical
		}
		desc := obj.Description
		if desc == "" {
			desc = obj.Name
		}
		matches := reSTIXPattern.FindAllStringSubmatch(obj.Pattern, -1)
		for _, m := range matches {
			lhs := strings.ToLower(m[1])
			val := strings.TrimSpace(m[2])
			kind := ""
			switch {
			case strings.HasPrefix(lhs, "ipv4-addr"), strings.HasPrefix(lhs, "ipv6-addr"):
				if strings.Contains(val, "/") {
					kind = "cidr"
				} else {
					kind = "ip"
				}
			case strings.HasPrefix(lhs, "domain-name"):
				kind = "domain"
			case strings.HasPrefix(lhs, "user-account"):
				kind = "user"
			case strings.HasPrefix(lhs, "file:hashes"):
				kind = "hash"
			}
			if kind != "" {
				if err := f.AddIndicator(Indicator{
					Value:       val,
					Kind:        kind,
					Severity:    sev,
					Source:      "stix:" + source,
					Description: desc,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (f *ThreatFeed) loadCSV(data []byte, source string) error {
	r := csv.NewReader(bytes.NewReader(data))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	lineNo := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("parse CSV threat intel %s: %w", source, err)
		}
		lineNo++
		if len(rec) == 0 {
			continue
		}
		val := strings.TrimSpace(rec[0])
		if val == "" || (lineNo == 1 && strings.EqualFold(val, "indicator")) {
			continue
		}
		kind := ""
		if len(rec) > 1 {
			kind = strings.ToLower(strings.TrimSpace(rec[1]))
		}
		sev := schema.SeverityHigh
		if len(rec) > 2 && strings.TrimSpace(rec[2]) != "" {
			if parsed, pErr := schema.ParseSeverity(rec[2]); pErr == nil {
				sev = parsed
			}
		}
		src := source
		if len(rec) > 3 && strings.TrimSpace(rec[3]) != "" {
			src = strings.TrimSpace(rec[3])
		}
		if err := f.AddIndicator(Indicator{Value: val, Kind: kind, Severity: sev, Source: src}); err != nil {
			return err
		}
	}
	return nil
}

func (f *ThreatFeed) loadPlaintext(data []byte, source string) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '#'); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if err := f.AddIndicator(Indicator{
			Value:    line,
			Severity: schema.SeverityHigh,
			Source:   source,
		}); err != nil {
			return err
		}
	}
	return sc.Err()
}

// AddIndicator compiles and indexes a single indicator inside f.
func (f *ThreatFeed) AddIndicator(ind Indicator) error {
	val := strings.TrimSpace(ind.Value)
	if val == "" {
		return nil
	}
	if ind.Severity == "" {
		ind.Severity = schema.SeverityHigh
	} else {
		parsed, err := schema.ParseSeverity(string(ind.Severity))
		if err != nil {
			return err
		}
		ind.Severity = parsed
	}
	kind := strings.ToLower(strings.TrimSpace(ind.Kind))
	if kind == "" {
		if strings.Contains(val, "/") {
			kind = "cidr"
		} else if _, err := netip.ParseAddr(val); err == nil {
			kind = "ip"
		} else {
			kind = "domain"
		}
	}
	ind.Kind = kind
	ind.Value = val

	switch kind {
	case "ip":
		addr, err := netip.ParseAddr(val)
		if err != nil {
			return fmt.Errorf("invalid IP indicator %q: %w", val, err)
		}
		f.ips[addr.String()] = ind
	case "cidr":
		pfx, err := netip.ParsePrefix(val)
		if err != nil {
			return fmt.Errorf("invalid CIDR indicator %q: %w", val, err)
		}
		f.cidrs = append(f.cidrs, cidrRule{prefix: pfx, indicator: ind})
	case "domain":
		f.domains[strings.ToLower(val)] = ind
	case "user":
		f.users[strings.ToLower(val)] = ind
	case "hash":
		f.hashes[strings.ToLower(val)] = ind
	default:
		return fmt.Errorf("unsupported threat indicator kind %q", ind.Kind)
	}
	f.count++
	return nil
}

// MatchEvent checks ev against all indexed IP, CIDR, domain, user, and hash indicators.
func (f *ThreatFeed) MatchEvent(ev schema.Event) []Match {
	if f == nil || f.count == 0 {
		return nil
	}
	var out []Match
	seen := make(map[string]bool)
	addHit := func(m Match) {
		key := m.MatchedOn + "|" + m.MatchedVal + "|" + m.Indicator.Value
		if !seen[key] {
			seen[key] = true
			out = append(out, m)
		}
	}

	checkIP := func(field, raw string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		if ind, ok := f.ips[addr.String()]; ok {
			addHit(Match{Indicator: ind, MatchedOn: field, MatchedVal: addr.String()})
		}
		for _, cr := range f.cidrs {
			if cr.prefix.Contains(addr) {
				addHit(Match{Indicator: cr.indicator, MatchedOn: field, MatchedVal: addr.String()})
			}
		}
	}

	if ev.SrcIP != "" {
		checkIP("src_ip", ev.SrcIP)
	}
	if ev.DstIP != "" {
		checkIP("dst_ip", ev.DstIP)
	}
	if ev.User != "" {
		if ind, ok := f.users[strings.ToLower(ev.User)]; ok {
			addHit(Match{Indicator: ind, MatchedOn: "user", MatchedVal: ev.User})
		}
	}
	if len(f.domains) > 0 {
		candidates := []string{ev.Host, ev.HTTPPath, ev.Message}
		if ev.Metadata != nil {
			if d := fmt.Sprint(ev.Metadata["domain"]); ev.Metadata["domain"] != nil {
				candidates = append(candidates, d)
			}
		}
		for _, cand := range candidates {
			low := strings.ToLower(cand)
			if low == "" {
				continue
			}
			for dom, ind := range f.domains {
				if low == dom || strings.Contains(low, dom) {
					addHit(Match{Indicator: ind, MatchedOn: "domain", MatchedVal: dom})
				}
			}
		}
	}
	if len(f.hashes) > 0 && ev.Metadata != nil {
		for _, key := range []string{"hash", "sha256", "md5", "ev_sha256"} {
			if val, ok := ev.Metadata[key]; ok && val != nil {
				hLow := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
				if ind, hit := f.hashes[hLow]; hit {
					addHit(Match{Indicator: ind, MatchedOn: "hash", MatchedVal: hLow})
				}
			}
		}
	}
	return out
}

// AssetEntry assigns a criticality tier and ownership metadata to a host, IP, or CIDR subnet.
type AssetEntry struct {
	Host   string   `yaml:"host" json:"host,omitempty"`
	IP     string   `yaml:"ip" json:"ip,omitempty"`
	CIDR   string   `yaml:"cidr" json:"cidr,omitempty"`
	Tier   string   `yaml:"tier" json:"tier"` // tier1 (critical), tier2 (high), tier3 (standard)
	Owner  string   `yaml:"owner" json:"owner,omitempty"`
	Tags   []string `yaml:"tags" json:"tags,omitempty"`
	prefix netip.Prefix
}

// AssetCatalog holds compiled asset criticality entries.
type AssetCatalog struct {
	byHost map[string]AssetEntry
	byIP   map[string]AssetEntry
	cidrs  []AssetEntry
}

// LoadAssetFile reads asset definitions from YAML or JSON.
func LoadAssetFile(path string) ([]AssetEntry, error) {
	clean := filepath.Clean(path)
	raw, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("read asset file %q: %w", clean, err)
	}
	var wrapped struct {
		Assets []AssetEntry `yaml:"assets" json:"assets"`
	}
	if err := yaml.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Assets) > 0 {
		return wrapped.Assets, nil
	}
	var list []AssetEntry
	if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse asset file %q: %w", clean, err)
	}
	return list, nil
}

// NewAssetCatalog compiles and validates entries into an AssetCatalog.
func NewAssetCatalog(entries []AssetEntry) (*AssetCatalog, error) {
	cat := &AssetCatalog{
		byHost: make(map[string]AssetEntry),
		byIP:   make(map[string]AssetEntry),
	}
	for i, e := range entries {
		tier := strings.ToLower(strings.TrimSpace(e.Tier))
		if tier == "" {
			tier = "tier2"
		}
		switch tier {
		case "tier1", "critical", "tier2", "high", "tier3", "standard":
		default:
			return nil, fmt.Errorf("assets[%d]: unsupported tier %q (use tier1, tier2, or tier3)", i, e.Tier)
		}
		e.Tier = tier
		if e.Host == "" && e.IP == "" && e.CIDR == "" {
			return nil, fmt.Errorf("assets[%d]: host, ip, or cidr is required", i)
		}
		if e.Host != "" {
			cat.byHost[strings.ToLower(strings.TrimSpace(e.Host))] = e
		}
		if e.IP != "" {
			addr, err := netip.ParseAddr(strings.TrimSpace(e.IP))
			if err != nil {
				return nil, fmt.Errorf("assets[%d]: invalid ip %q: %w", i, e.IP, err)
			}
			cat.byIP[addr.String()] = e
		}
		if e.CIDR != "" {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(e.CIDR))
			if err != nil {
				return nil, fmt.Errorf("assets[%d]: invalid cidr %q: %w", i, e.CIDR, err)
			}
			e.prefix = pfx
			cat.cidrs = append(cat.cidrs, e)
		}
	}
	return cat, nil
}

// LookupEvent locates the most specific matching AssetEntry for ev.
func (c *AssetCatalog) LookupEvent(ev schema.Event) (AssetEntry, bool) {
	if c == nil {
		return AssetEntry{}, false
	}
	return c.LookupHostOrIP(ev.Host, firstNonEmpty(ev.DstIP, ev.SrcIP))
}

// LookupHostOrIP locates a matching AssetEntry by host name, exact IP, or CIDR.
func (c *AssetCatalog) LookupHostOrIP(host, ip string) (AssetEntry, bool) {
	if c == nil {
		return AssetEntry{}, false
	}
	if h := strings.ToLower(strings.TrimSpace(host)); h != "" {
		if e, ok := c.byHost[h]; ok {
			return e, true
		}
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		if e, ok := c.byIP[addr.String()]; ok {
			return e, true
		}
		for _, ce := range c.cidrs {
			if ce.prefix.Contains(addr) {
				return ce, true
			}
		}
	}
	return AssetEntry{}, false
}

// EscalateSeverity bumps incident severity by one rank on tier1/critical assets.
func EscalateSeverity(base schema.Severity, tier string) (schema.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "tier1", "critical":
		switch base {
		case schema.SeverityLow:
			return schema.SeverityMedium, true
		case schema.SeverityMedium:
			return schema.SeverityHigh, true
		case schema.SeverityHigh:
			return schema.SeverityCritical, true
		}
	}
	return base, false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
