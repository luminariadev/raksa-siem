package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

const (
	sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	repoURI        = "https://github.com/luminariadev/raksa-siem"
)

// OutputFormat identifies supported rendered report encodings.
type OutputFormat string

const (
	FormatTable    OutputFormat = "table"
	FormatJSON     OutputFormat = "json"
	FormatSARIF    OutputFormat = "sarif"
	FormatMarkdown OutputFormat = "markdown"
	FormatNDJSON   OutputFormat = "ndjson"
)

// ParseFormat normalizes output format selection strings.
func ParseFormat(raw string) (OutputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "table":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	case "ndjson":
		return FormatNDJSON, nil
	default:
		return "", fmt.Errorf("invalid output format %q: expected table, json, sarif, markdown, or ndjson", raw)
	}
}

// FormatReport renders a schema.Report into the requested format string.
func FormatReport(rep schema.Report, format OutputFormat) (string, error) {
	switch format {
	case FormatTable:
		return FormatTableRender(rep), nil
	case FormatJSON:
		return FormatJSONRender(rep)
	case FormatSARIF:
		return FormatSARIFRender(rep)
	case FormatMarkdown:
		return FormatMarkdownRender(rep), nil
	case FormatNDJSON:
		return FormatNDJSONRender(rep)
	default:
		return "", fmt.Errorf("unsupported output format %q", format)
	}
}

// WriteReport renders and writes a Report to w.
func WriteReport(w io.Writer, rep schema.Report, format OutputFormat) error {
	rendered, err := FormatReport(rep, format)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, rendered)
	return err
}

// SanitizeTerminal removes ANSI escape sequences and C0/C1 control characters cleanly.
func SanitizeTerminal(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		if raw[i] == 0x1b {
			if i+1 < len(raw) && raw[i+1] == '[' {
				i += 2
				for i < len(raw) {
					c := raw[i]
					i++
					if c >= '@' && c <= '~' {
						break
					}
				}
				continue
			}
			if i+1 < len(raw) && raw[i+1] == ']' {
				i += 2
				for i < len(raw) {
					if raw[i] == 0x07 {
						i++
						break
					}
					if raw[i] == 0x1b && i+1 < len(raw) && raw[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(raw[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			continue
		}
		if r == '\t' || r == '\n' || r == '\r' {
			b.WriteByte(' ')
		} else if r >= 0x20 && r != 0x7f && !(r >= 0x80 && r <= 0x9f) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// FormatTableRender formats an ANSI-safe terminal summary table.
func FormatTableRender(rep schema.Report) string {
	var b strings.Builder
	scoreSuffix := ""
	if rep.Posture != nil {
		scoreSuffix = fmt.Sprintf(" | score: %d/100 (%s)", rep.Posture.Score, SanitizeTerminal(rep.Posture.Grade))
	}
	fmt.Fprintf(
		&b,
		"%s v%s | layer: %s%s | total: %d (critical: %d, high: %d, medium: %d, low: %d, info: %d)\n",
		SanitizeTerminal(rep.Tool),
		schema.Version,
		SanitizeTerminal(rep.Layer),
		scoreSuffix,
		rep.Summary.Total,
		rep.Summary.Critical,
		rep.Summary.High,
		rep.Summary.Medium,
		rep.Summary.Low,
		rep.Summary.Info,
	)
	if len(rep.Findings) == 0 {
		b.WriteString("No correlated SIEM security incidents detected.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "%-9s %-9s %-12s %-34s %s\n", "RULE", "SEVERITY", "MODULE", "TARGET", "TITLE")
	fmt.Fprintf(&b, "%-9s %-9s %-12s %-34s %s\n", strings.Repeat("-", 9), strings.Repeat("-", 9), strings.Repeat("-", 12), strings.Repeat("-", 34), strings.Repeat("-", 32))
	for _, f := range rep.Findings {
		tgt := SanitizeTerminal(f.Target)
		if len(tgt) > 34 {
			tgt = "..." + tgt[len(tgt)-31:]
		}
		fmt.Fprintf(
			&b,
			"%-9s %-9s %-12s %-34s %s\n",
			SanitizeTerminal(f.RuleID),
			SanitizeTerminal(string(f.Severity)),
			SanitizeTerminal(f.Module),
			tgt,
			SanitizeTerminal(f.Title),
		)
	}
	return b.String()
}

// FormatJSONRender serializes the Report envelope as indented JSON.
func FormatJSONRender(rep schema.Report) (string, error) {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal json report: %w", err)
	}
	return string(data) + "\n", nil
}

// FormatNDJSONRender serializes each Finding as one compact JSON object per line.
func FormatNDJSONRender(rep schema.Report) (string, error) {
	if len(rep.Findings) == 0 {
		return "", nil
	}
	var b strings.Builder
	for _, f := range rep.Findings {
		raw, err := json.Marshal(f)
		if err != nil {
			return "", fmt.Errorf("marshal ndjson finding %s: %w", f.ID, err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// FormatMarkdownRender emits a Markdown triage summary report.
func FormatMarkdownRender(rep schema.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Raksa SIEM Security Report (`v%s`)\n\n", schema.Version)
	fmt.Fprintf(&b, "- **Layer**: `%s`\n", SanitizeTerminal(rep.Layer))
	if rep.Posture != nil {
		fmt.Fprintf(&b, "- **Posture**: **%d/100 (`%s`)**\n", rep.Posture.Score, SanitizeTerminal(rep.Posture.Grade))
	}
	fmt.Fprintf(
		&b,
		"- **Findings**: %d total (`%d` critical, `%d` high, `%d` medium, `%d` low, `%d` info)\n\n",
		rep.Summary.Total,
		rep.Summary.Critical,
		rep.Summary.High,
		rep.Summary.Medium,
		rep.Summary.Low,
		rep.Summary.Info,
	)
	if len(rep.Findings) == 0 {
		b.WriteString("No correlated SIEM incidents detected.\n")
		return b.String()
	}
	b.WriteString("| Rule | Severity | Module | Target | Title | MITRE D3FEND |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, f := range rep.Findings {
		fmt.Fprintf(
			&b,
			"| `%s` | `%s` | `%s` | `%s` | %s | `%s` |\n",
			SanitizeTerminal(f.RuleID),
			SanitizeTerminal(string(f.Severity)),
			SanitizeTerminal(f.Module),
			escapeMarkdownCell(SanitizeTerminal(f.Target)),
			escapeMarkdownCell(SanitizeTerminal(f.Title)),
			SanitizeTerminal(f.MitreD3FEND),
		)
	}
	return b.String()
}

func escapeMarkdownCell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// FormatSARIFRender produces a deterministic SARIF 2.1.0 JSON envelope containing all 20 built-in rules.
func FormatSARIFRender(rep schema.Report) (string, error) {
	rules := make([]map[string]any, 0, 24)
	seenRules := make(map[string]bool)
	for _, r := range schema.RuleCatalog() {
		seenRules[r.RuleID] = true
		rules = append(rules, sarifRuleEntry(r.RuleID, r.Title, r.Description, r.Severity, r.MitreD3FEND, r.Standard))
	}
	var extraIDs []string
	for _, f := range rep.Findings {
		if !seenRules[f.RuleID] {
			seenRules[f.RuleID] = true
			extraIDs = append(extraIDs, f.RuleID)
		}
	}
	sort.Strings(extraIDs)
	for _, rid := range extraIDs {
		for _, f := range rep.Findings {
			if f.RuleID == rid {
				rules = append(rules, sarifRuleEntry(f.RuleID, f.Title, f.Description, f.Severity, f.MitreD3FEND, "Custom Rule"))
				break
			}
		}
	}

	results := make([]map[string]any, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		locURI := f.Target
		if locURI == "" {
			locURI = "siem://telemetry"
		}
		results = append(results, map[string]any{
			"ruleId": f.RuleID,
			"level":  sarifLevel(f.Severity),
			"message": map[string]any{
				"text": fmt.Sprintf("%s: %s", f.Title, f.Description),
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{
							"uri": locURI,
						},
					},
				},
			},
			"properties": map[string]any{
				"id":           f.ID,
				"module":       f.Module,
				"mitre_d3fend": f.MitreD3FEND,
				"remediation":  f.Remediation,
				"evidence":     f.Evidence,
			},
		})
	}

	sarifObj := map[string]any{
		"$schema": sarifSchemaURI,
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           rep.Tool,
						"version":        schema.Version,
						"informationUri": repoURI,
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}

	raw, err := json.MarshalIndent(sarifObj, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal sarif report: %w", err)
	}
	return string(raw) + "\n", nil
}

func sarifRuleEntry(id, title, desc string, sev schema.Severity, d3fend, std string) map[string]any {
	return map[string]any{
		"id":               id,
		"name":             title,
		"shortDescription": map[string]any{"text": title},
		"fullDescription":  map[string]any{"text": desc},
		"defaultConfiguration": map[string]any{
			"level": sarifLevel(sev),
		},
		"properties": map[string]any{
			"mitre_d3fend": d3fend,
			"standard":     std,
		},
	}
}

func sarifLevel(sev schema.Severity) string {
	switch sev {
	case schema.SeverityCritical, schema.SeverityHigh:
		return "error"
	case schema.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
