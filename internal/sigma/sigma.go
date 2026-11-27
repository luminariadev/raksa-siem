package sigma

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

// AggregationSpec describes an optional piped aggregation expression such as
// `selection | count() by src_ip >= 5` inside Sigma detection blocks.
type AggregationSpec struct {
	DistinctField string `json:"distinct_field,omitempty"`
	GroupBy       string `json:"group_by,omitempty"`
	Op            string `json:"op"`
	Threshold     int    `json:"threshold"`
}

// LogSource holds optional Sigma metadata filtering target log categories/products.
type LogSource struct {
	Category string `yaml:"category" json:"category,omitempty"`
	Product  string `yaml:"product" json:"product,omitempty"`
	Service  string `yaml:"service" json:"service,omitempty"`
}

// Rule is a compiled native Sigma YAML detection rule ready for thread-safe evaluation.
type Rule struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Status         string          `json:"status,omitempty"`
	Description    string          `json:"description,omitempty"`
	Author         string          `json:"author,omitempty"`
	Level          schema.Severity `json:"level"`
	Tags           []string        `json:"tags,omitempty"`
	MitreTechnique string          `json:"mitre_technique,omitempty"`
	LogSource      LogSource       `json:"logsource,omitempty"`
	ConditionRaw   string          `json:"condition"`
	Timeframe      time.Duration   `json:"timeframe"`
	Aggregation    *AggregationSpec `json:"aggregation,omitempty"`
	SourcePath     string          `json:"source_path,omitempty"`

	selections map[string]matcher
	condNode   condExpr
}

// LoadPath reads a single YAML file or recursively loads all .yml/.yaml Sigma rule files in a directory.
func LoadPath(path string) ([]*Rule, error) {
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("stat sigma path %q: %w", path, err)
	}
	if !info.IsDir() {
		raw, err := os.ReadFile(clean)
		if err != nil {
			return nil, fmt.Errorf("read sigma file %q: %w", clean, err)
		}
		return ParseBytes(raw, clean)
	}

	var all []*Rule
	err = filepath.WalkDir(clean, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		raw, readErr := os.ReadFile(p)
		if readErr != nil {
			return fmt.Errorf("read sigma file %q: %w", p, readErr)
		}
		rules, parseErr := ParseBytes(raw, p)
		if parseErr != nil {
			return parseErr
		}
		all = append(all, rules...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

// ParseBytes compiles one or more multi-document YAML Sigma rules from raw bytes.
func ParseBytes(data []byte, sourceName string) ([]*Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var rules []*Rule
	docIdx := 0

	for {
		var raw map[string]any
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse sigma YAML %s (doc %d): %w", sourceName, docIdx, err)
		}
		docIdx++
		if len(raw) == 0 {
			continue
		}
		// Skip pure collection metadata documents without detection sections (e.g. non-Sigma config)
		detRaw, hasDet := raw["detection"].(map[string]any)
		if !hasDet {
			return nil, fmt.Errorf("sigma %s (doc %d): missing detection block", sourceName, docIdx)
		}
		rule, err := compileRuleDoc(raw, detRaw, sourceName, docIdx)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("sigma %s contains no rules", sourceName)
	}
	return rules, nil
}

func compileRuleDoc(raw, detRaw map[string]any, sourceName string, docIdx int) (*Rule, error) {
	title := asString(raw["title"])
	if title == "" {
		return nil, fmt.Errorf("sigma %s (doc %d): title is required", sourceName, docIdx)
	}
	id := asString(raw["id"])
	if id == "" {
		id = fmt.Sprintf("SIGMA-%s-%d", filepath.Base(sourceName), docIdx)
	}

	sev := schema.SeverityHigh
	if lvl := strings.ToLower(asString(raw["level"])); lvl != "" {
		switch lvl {
		case "informational", "info":
			sev = schema.SeverityInfo
		case "low":
			sev = schema.SeverityLow
		case "medium":
			sev = schema.SeverityMedium
		case "high":
			sev = schema.SeverityHigh
		case "critical":
			sev = schema.SeverityCritical
		default:
			return nil, fmt.Errorf("sigma %s (%s): unsupported level %q", sourceName, id, lvl)
		}
	}

	var tags []string
	var mitre []string
	if rawTags, ok := raw["tags"].([]any); ok {
		for _, item := range rawTags {
			t := asString(item)
			if t == "" {
				continue
			}
			tags = append(tags, t)
			lower := strings.ToLower(t)
			if strings.HasPrefix(lower, "attack.t") {
				mitre = append(mitre, strings.ToUpper(strings.TrimPrefix(lower, "attack.")))
			}
		}
	}

	var ls LogSource
	if lsMap, ok := raw["logsource"].(map[string]any); ok {
		ls.Category = strings.ToLower(asString(lsMap["category"]))
		ls.Product = strings.ToLower(asString(lsMap["product"]))
		ls.Service = strings.ToLower(asString(lsMap["service"]))
	}

	condRaw := asString(detRaw["condition"])
	if condRaw == "" {
		return nil, fmt.Errorf("sigma %s (%s): detection.condition is required", sourceName, id)
	}

	timeframe := 5 * time.Minute
	if tfRaw := asString(detRaw["timeframe"]); tfRaw != "" {
		d, err := parseSigmaDuration(tfRaw)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("sigma %s (%s): invalid detection.timeframe %q", sourceName, id, tfRaw)
		}
		timeframe = d
	}

	selections := make(map[string]matcher)
	for k, v := range detRaw {
		if k == "condition" || k == "timeframe" {
			continue
		}
		m, err := compileSelection(k, v)
		if err != nil {
			return nil, fmt.Errorf("sigma %s (%s): %w", sourceName, id, err)
		}
		selections[k] = m
	}
	if len(selections) == 0 {
		return nil, fmt.Errorf("sigma %s (%s): detection must define at least one selection", sourceName, id)
	}

	baseCond, aggSpec, err := splitAggregation(condRaw)
	if err != nil {
		return nil, fmt.Errorf("sigma %s (%s): %w", sourceName, id, err)
	}
	ast, err := parseCondition(baseCond, selections)
	if err != nil {
		return nil, fmt.Errorf("sigma %s (%s): invalid condition %q: %w", sourceName, id, condRaw, err)
	}

	return &Rule{
		ID:             id,
		Title:          title,
		Status:         asString(raw["status"]),
		Description:    asString(raw["description"]),
		Author:         asString(raw["author"]),
		Level:          sev,
		Tags:           tags,
		MitreTechnique: strings.Join(mitre, ", "),
		LogSource:      ls,
		ConditionRaw:   condRaw,
		Timeframe:      timeframe,
		Aggregation:    aggSpec,
		SourcePath:     sourceName,
		selections:     selections,
		condNode:       ast,
	}, nil
}

// HasAggregation returns true if the Sigma condition includes a piped count() aggregation.
func (r *Rule) HasAggregation() bool {
	return r != nil && r.Aggregation != nil
}

// MatchesEvent evaluates the boolean base condition (and logsource hints if specified) against ev.
func (r *Rule) MatchesEvent(ev schema.Event) bool {
	if r == nil || r.condNode == nil {
		return false
	}
	if !r.matchesLogSource(ev) {
		return false
	}
	return r.condNode.eval(ev, r.selections)
}

// GroupValue resolves the aggregation group_by field value on ev.
func (r *Rule) GroupValue(ev schema.Event) string {
	if r == nil || r.Aggregation == nil || strings.TrimSpace(r.Aggregation.GroupBy) == "" {
		return "global"
	}
	vals := eventFieldValues(ev, r.Aggregation.GroupBy)
	if len(vals) > 0 && vals[0] != "" {
		return vals[0]
	}
	return "unknown"
}

func (r *Rule) matchesLogSource(ev schema.Event) bool {
	ls := r.LogSource
	if ls.Product != "" {
		switch ls.Product {
		case "aws":
			if ev.SourceFormat != "cloudtrail" && ev.Layer != "cloud-audit" {
				return false
			}
		case "kubernetes", "k8s":
			if ev.SourceFormat != "k8s-audit" {
				return false
			}
		case "windows":
			if ev.SourceFormat != "win-evtx" && ev.SourceFormat != "jsonl" {
				return false
			}
		case "linux":
			if ev.SourceFormat != "auth" && ev.SourceFormat != "syslog" && ev.SourceFormat != "auditd" && ev.Layer != "host-hardening" {
				return false
			}
		case "nginx", "webserver":
			if ev.SourceFormat != "nginx" && ev.Category != "web" {
				return false
			}
		}
	}
	if ls.Category != "" {
		switch ls.Category {
		case "process_creation":
			if ev.Category != "process" && ev.Action != "exec" && len(eventFieldValues(ev, "CommandLine")) == 0 {
				return false
			}
		case "webserver":
			if ev.Category != "web" {
				return false
			}
		}
	}
	return true
}

type matcher interface {
	match(ev schema.Event) bool
}

type allMatcher []matcher
type anyMatcher []matcher

func (m allMatcher) match(ev schema.Event) bool {
	if len(m) == 0 {
		return false
	}
	for _, sub := range m {
		if !sub.match(ev) {
			return false
		}
	}
	return true
}

func (m anyMatcher) match(ev schema.Event) bool {
	for _, sub := range m {
		if sub.match(ev) {
			return true
		}
	}
	return false
}

type keywordMatcher struct {
	pred valuePredicate
	all  bool
}

func (m keywordMatcher) match(ev schema.Event) bool {
	haystack := ev.Message + "\n" + ev.Raw
	if cmd, ok := ev.Metadata["command_line"]; ok {
		haystack += "\n" + fmt.Sprint(cmd)
	}
	return m.pred.match([]string{haystack})
}

type fieldMatcher struct {
	field string
	pred  valuePredicate
}

func (m fieldMatcher) match(ev schema.Event) bool {
	vals := eventFieldValues(ev, m.field)
	if len(vals) == 0 {
		return false
	}
	return m.pred.match(vals)
}

type valuePredicate struct {
	op       string // equal, wildcard, contains, startswith, endswith, regex, cidr, base64
	cased    bool
	all      bool
	literals []string
	regexps  []*regexp.Regexp
	prefixes []netip.Prefix
}

func (vp valuePredicate) match(fieldVals []string) bool {
	if len(vp.literals) == 0 && len(vp.regexps) == 0 && len(vp.prefixes) == 0 {
		return false
	}

	if vp.op == "cidr" {
		matchedPrefix := make([]bool, len(vp.prefixes))
		for _, v := range fieldVals {
			addr, err := netip.ParseAddr(strings.TrimSpace(v))
			if err != nil {
				continue
			}
			for i, pfx := range vp.prefixes {
				if pfx.Contains(addr) {
					matchedPrefix[i] = true
				}
			}
		}
		if vp.all {
			for _, ok := range matchedPrefix {
				if !ok {
					return false
				}
			}
			return true
		}
		for _, ok := range matchedPrefix {
			if ok {
				return true
			}
		}
		return false
	}

	if vp.op == "regex" || vp.op == "wildcard" {
		matchedRe := make([]bool, len(vp.regexps))
		for _, v := range fieldVals {
			for i, re := range vp.regexps {
				if re.MatchString(v) {
					matchedRe[i] = true
				}
			}
		}
		if vp.all {
			for _, ok := range matchedRe {
				if !ok {
					return false
				}
			}
			return true
		}
		for _, ok := range matchedRe {
			if ok {
				return true
			}
		}
		return false
	}

	matchedLit := make([]bool, len(vp.literals))
	for _, rawVal := range fieldVals {
		val := rawVal
		if !vp.cased && vp.op != "base64" {
			val = strings.ToLower(rawVal)
		}
		for i, pat := range vp.literals {
			p := pat
			if !vp.cased && vp.op != "base64" {
				p = strings.ToLower(pat)
			}
			var hit bool
			switch vp.op {
			case "equal":
				hit = val == p
			case "contains", "base64":
				hit = strings.Contains(val, p)
			case "startswith":
				hit = strings.HasPrefix(val, p)
			case "endswith":
				hit = strings.HasSuffix(val, p)
			}
			if hit {
				matchedLit[i] = true
			}
		}
	}
	if vp.all {
		for _, ok := range matchedLit {
			if !ok {
				return false
			}
		}
		return true
	}
	for _, ok := range matchedLit {
		if ok {
			return true
		}
	}
	return false
}

func compileSelection(name string, raw any) (matcher, error) {
	switch node := raw.(type) {
	case map[string]any:
		return compileFieldMap(name, node)
	case []any:
		if len(node) == 0 {
			return nil, fmt.Errorf("selection %q cannot be empty", name)
		}
		// Detect keyword list (strings/ints) vs list of field maps (ORed)
		if _, isMap := node[0].(map[string]any); isMap {
			var orList anyMatcher
			for i, item := range node {
				m, ok := item.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("selection %q[%d]: mixed list item types not allowed", name, i)
				}
				compiled, err := compileFieldMap(fmt.Sprintf("%s[%d]", name, i), m)
				if err != nil {
					return nil, err
				}
				orList = append(orList, compiled)
			}
			return orList, nil
		}
		pred, err := compilePredicate(name, "contains", false, false, node)
		if err != nil {
			return nil, err
		}
		return keywordMatcher{pred: pred}, nil
	default:
		return nil, fmt.Errorf("selection %q: expected map or list", name)
	}
}

func compileFieldMap(name string, fields map[string]any) (matcher, error) {
	var andGroup allMatcher
	for key, val := range fields {
		parts := strings.Split(key, "|")
		fieldName := strings.TrimSpace(parts[0])
		if fieldName == "" {
			return nil, fmt.Errorf("selection %q: empty field name in %q", name, key)
		}
		op := "wildcard"
		cased := false
		requireAll := false
		for _, mod := range parts[1:] {
			switch strings.ToLower(strings.TrimSpace(mod)) {
			case "contains":
				op = "contains"
			case "startswith":
				op = "startswith"
			case "endswith":
				op = "endswith"
			case "re":
				op = "regex"
			case "cidr":
				op = "cidr"
			case "base64":
				op = "base64"
			case "all":
				requireAll = true
			case "cased":
				cased = true
			case "":
			default:
				return nil, fmt.Errorf("selection %q: unsupported modifier %q in %q", name, mod, key)
			}
		}

		var rawVals []any
		switch typed := val.(type) {
		case []any:
			rawVals = typed
		default:
			rawVals = []any{typed}
		}
		pred, err := compilePredicate(name+"."+key, op, cased, requireAll, rawVals)
		if err != nil {
			return nil, err
		}
		andGroup = append(andGroup, fieldMatcher{field: fieldName, pred: pred})
	}
	return andGroup, nil
}

func compilePredicate(label, op string, cased, requireAll bool, rawVals []any) (valuePredicate, error) {
	if len(rawVals) == 0 {
		return valuePredicate{}, fmt.Errorf("%s: empty value list", label)
	}
	vp := valuePredicate{op: op, cased: cased, all: requireAll}

	for _, item := range rawVals {
		if item == nil {
			continue
		}
		s := asString(item)
		switch op {
		case "cidr":
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				addr, err2 := netip.ParseAddr(s)
				if err2 != nil {
					return vp, fmt.Errorf("%s: invalid CIDR/IP %q: %w", label, s, err)
				}
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				pfx = netip.PrefixFrom(addr, bits)
			}
			vp.prefixes = append(vp.prefixes, pfx)

		case "regex":
			re, err := regexp.Compile(s)
			if err != nil {
				return vp, fmt.Errorf("%s: invalid regex %q: %w", label, s, err)
			}
			vp.regexps = append(vp.regexps, re)

		case "base64":
			variants := base64OffsetVariants(s)
			vp.literals = append(vp.literals, variants...)

		case "wildcard":
			if strings.ContainsAny(s, "*?") {
				re, err := compileWildcardRegex(s, cased)
				if err != nil {
					return vp, fmt.Errorf("%s: compile wildcard %q: %w", label, s, err)
				}
				vp.regexps = append(vp.regexps, re)
			} else {
				vp.op = "equal"
				vp.literals = append(vp.literals, s)
			}

		default:
			vp.literals = append(vp.literals, s)
		}
	}
	if op == "wildcard" && len(vp.literals) > 0 && len(vp.regexps) > 0 {
		// Mixed literals and globs: compile literals into exact regexps too for unified regex evaluation
		for _, lit := range vp.literals {
			re, err := compileWildcardRegex(lit, cased)
			if err == nil {
				vp.regexps = append(vp.regexps, re)
			}
		}
		vp.literals = nil
		vp.op = "regex"
	}
	return vp, nil
}

func compileWildcardRegex(pattern string, cased bool) (*regexp.Regexp, error) {
	var b strings.Builder
	if !cased {
		b.WriteString("(?is)^")
	} else {
		b.WriteString("(?s)^")
	}
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

// base64OffsetVariants produces Sigma's standard 3 byte-alignment base64 substrings.
func base64OffsetVariants(plain string) []string {
	b := []byte(plain)
	out := make([]string, 0, 3)
	// Offset 0: drop trailing '=' padding that depends on following plaintext
	s0 := strings.TrimRight(base64.StdEncoding.EncodeToString(b), "=")
	if len(b)%3 == 1 && len(s0) > 2 {
		s0 = s0[:len(s0)-1]
	} else if len(b)%3 == 2 && len(s0) > 1 {
		s0 = s0[:len(s0)-1]
	}
	if s0 != "" {
		out = append(out, s0)
	}
	// Offset 1 & 2: prepend dummy prefix byte(s) and strip first 2/3 base64 chars
	for pad := 1; pad <= 2; pad++ {
		prefixed := append(make([]byte, pad), b...)
		enc := strings.TrimRight(base64.StdEncoding.EncodeToString(prefixed), "=")
		dropStart := pad + 1
		if len(enc) > dropStart {
			sub := enc[dropStart:]
			if (len(prefixed))%3 != 0 && len(sub) > 1 {
				sub = sub[:len(sub)-1]
			}
			if sub != "" {
				out = append(out, sub)
			}
		}
	}
	if len(out) == 0 {
		return []string{base64.StdEncoding.EncodeToString(b)}
	}
	return out
}

type condExpr interface {
	eval(ev schema.Event, selections map[string]matcher) bool
}

type refExpr struct{ name string }
type ofExpr struct {
	all     bool
	pattern string // "" when targeting "them"
}
type notExpr struct{ child condExpr }
type andExpr struct{ left, right condExpr }
type orExpr struct{ left, right condExpr }

func (e refExpr) eval(ev schema.Event, selections map[string]matcher) bool {
	m, ok := selections[e.name]
	if !ok {
		return false
	}
	return m.match(ev)
}

func (e ofExpr) eval(ev schema.Event, selections map[string]matcher) bool {
	matchedCount := 0
	total := 0
	for name, m := range selections {
		if e.pattern != "" && !globMatchASCII(e.pattern, name) {
			continue
		}
		total++
		ok := m.match(ev)
		if !e.all && ok {
			return true
		}
		if ok {
			matchedCount++
		}
	}
	if e.all {
		return total > 0 && matchedCount == total
	}
	return false
}

func (e notExpr) eval(ev schema.Event, selections map[string]matcher) bool {
	return !e.child.eval(ev, selections)
}

func (e andExpr) eval(ev schema.Event, selections map[string]matcher) bool {
	return e.left.eval(ev, selections) && e.right.eval(ev, selections)
}

func (e orExpr) eval(ev schema.Event, selections map[string]matcher) bool {
	return e.left.eval(ev, selections) || e.right.eval(ev, selections)
}

var reAggPipe = regexp.MustCompile(`^(.*?)\|\s*count\(([^)]*)\)\s*(?:by\s+([^\s><=]+)\s*)?(>=|<=|==|>|<|=)\s*(\d+)\s*$`)

func splitAggregation(cond string) (string, *AggregationSpec, error) {
	if !strings.Contains(cond, "|") {
		return cond, nil, nil
	}
	m := reAggPipe.FindStringSubmatch(strings.TrimSpace(cond))
	if m == nil {
		return "", nil, fmt.Errorf("unsupported Sigma pipe aggregation %q", cond)
	}
	base := strings.TrimSpace(m[1])
	distinct := strings.TrimSpace(m[2])
	groupBy := strings.TrimSpace(m[3])
	op := m[4]
	if op == "=" {
		op = "=="
	}
	thr, err := strconv.Atoi(m[5])
	if err != nil || thr <= 0 {
		return "", nil, fmt.Errorf("invalid aggregation threshold %q", m[5])
	}
	return base, &AggregationSpec{
		DistinctField: distinct,
		GroupBy:       groupBy,
		Op:            op,
		Threshold:     thr,
	}, nil
}

type condParser struct {
	tokens     []string
	pos        int
	selections map[string]matcher
}

func tokenizeCondition(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '(' || c == ')':
			flush()
			tokens = append(tokens, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	if len(tokens) == 0 {
		return nil, errors.New("empty condition")
	}
	return tokens, nil
}

func parseCondition(cond string, selections map[string]matcher) (condExpr, error) {
	toks, err := tokenizeCondition(cond)
	if err != nil {
		return nil, err
	}
	p := &condParser{tokens: toks, selections: selections}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("unexpected token %q", p.tokens[p.pos])
	}
	return expr, nil
}

func (p *condParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *condParser) parseOr() (condExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orExpr{left: left, right: right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (condExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.pos++
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andExpr{left: left, right: right}
	}
	return left, nil
}

func (p *condParser) parseNot() (condExpr, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.pos++
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notExpr{child: child}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condExpr, error) {
	tok := p.peek()
	if tok == "" {
		return nil, errors.New("unexpected end of condition")
	}
	if tok == "(" {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing closing ')'")
		}
		p.pos++
		return inner, nil
	}
	if (tok == "1" || strings.EqualFold(tok, "all")) && p.pos+2 < len(p.tokens) && strings.EqualFold(p.tokens[p.pos+1], "of") {
		isAll := strings.EqualFold(tok, "all")
		target := p.tokens[p.pos+2]
		p.pos += 3
		if strings.EqualFold(target, "them") {
			return ofExpr{all: isAll, pattern: ""}, nil
		}
		if err := validateOfPattern(target, p.selections); err != nil {
			return nil, err
		}
		return ofExpr{all: isAll, pattern: target}, nil
	}

	p.pos++
	if _, ok := p.selections[tok]; !ok {
		return nil, fmt.Errorf("unknown selection identifier %q", tok)
	}
	return refExpr{name: tok}, nil
}

func validateOfPattern(pat string, selections map[string]matcher) error {
	for name := range selections {
		if globMatchASCII(pat, name) {
			return nil
		}
	}
	return fmt.Errorf("selection pattern %q matches zero defined selections", pat)
}

func globMatchASCII(pat, val string) bool {
	matched, err := filepath.Match(pat, val)
	if err != nil {
		return pat == val
	}
	return matched
}

func parseSigmaDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if strings.HasSuffix(raw, "d") {
		daysStr := strings.TrimSuffix(raw, "d")
		days, err := strconv.Atoi(daysStr)
		if err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(raw)
}

func eventFieldValues(ev schema.Event, field string) []string {
	var out []string
	add := func(v string) {
		if v != "" {
			out = append(out, v)
		}
	}
	norm := strings.ToLower(strings.TrimSpace(field))
	switch norm {
	case "commandline", "command_line", "proctitle", "cmd":
		if ev.Metadata != nil {
			if s := fmt.Sprint(ev.Metadata["command_line"]); ev.Metadata["command_line"] != nil && s != "" {
				add(s)
			}
		}
		add(ev.Message)
	case "image", "process", "processname", "newprocessname", "exe":
		add(ev.Process)
		add(ev.Path)
	case "user", "username", "targetusername", "subjectusername", "account":
		add(ev.User)
	case "src_ip", "sourceip", "ipaddress", "clientip", "source_ip", "src":
		add(ev.SrcIP)
	case "dst_ip", "dest_ip", "destinationip", "dst":
		add(ev.DstIP)
	case "dst_port", "dest_port", "destinationport", "port":
		if ev.DstPort > 0 {
			add(strconv.Itoa(ev.DstPort))
		}
	case "host", "hostname", "computer", "computername", "node", "devname":
		add(ev.Host)
	case "eventid", "event_id", "rule_id", "ruleid":
		if ev.Metadata != nil && ev.Metadata["event_id"] != nil {
			add(fmt.Sprint(ev.Metadata["event_id"]))
		}
		add(ev.RuleID)
	case "eventname", "event_name":
		if ev.Metadata != nil && ev.Metadata["event_name"] != nil {
			add(fmt.Sprint(ev.Metadata["event_name"]))
		}
		add(ev.Action)
	case "eventsource", "event_source":
		if ev.Metadata != nil && ev.Metadata["event_source"] != nil {
			add(fmt.Sprint(ev.Metadata["event_source"]))
		}
		add(ev.Tool)
	case "cs-uri-stem", "uri", "requesturi", "http_path", "url":
		add(ev.HTTPPath)
		add(ev.Path)
	case "cs-method", "method", "http_method":
		add(ev.HTTPMethod)
	case "sc-status", "status", "http_status":
		if ev.HTTPStatus > 0 {
			add(strconv.Itoa(ev.HTTPStatus))
		}
	case "query", "rrname", "domain":
		if ev.Metadata != nil && ev.Metadata["domain"] != nil {
			add(fmt.Sprint(ev.Metadata["domain"]))
		}
		add(ev.Host)
	case "targetfilename", "path", "file", "file_path", "resource":
		add(ev.Path)
		if ev.Metadata != nil && ev.Metadata["k8s_resource"] != nil {
			add(fmt.Sprint(ev.Metadata["k8s_resource"]))
		}
	case "layer":
		add(ev.Layer)
	case "category":
		add(ev.Category)
	case "action", "verb":
		add(ev.Action)
	case "outcome":
		add(ev.Outcome)
	case "severity", "level":
		add(string(ev.Severity))
	case "tool":
		add(ev.Tool)
	case "source_format":
		add(ev.SourceFormat)
	case "message", "msg":
		add(ev.Message)
	case "raw":
		add(ev.Raw)
	}

	if ev.Metadata != nil {
		for k, v := range ev.Metadata {
			if strings.EqualFold(k, field) || strings.EqualFold(k, "ev_"+field) {
				if v != nil {
					s := strings.TrimSpace(fmt.Sprintf("%v", v))
					if s != "" && s != "<nil>" {
						add(s)
					}
				}
			}
		}
	}
	return out
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}
