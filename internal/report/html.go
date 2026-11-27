package report

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/luminariadev/raksa-siem/internal/schema"
)

// FormatHTMLRender produces a self-contained single-file dark-mode HTML5 triage report
// with an inline SVG attack graph, posture gauge, and client-side filtering (zero external CDNs).
func FormatHTMLRender(rep schema.Report) string {
	score := 100
	grade := "A+"
	if rep.Posture != nil {
		score = rep.Posture.Score
		grade = rep.Posture.Grade
	}
	genAt := rep.GeneratedAt
	if genAt.IsZero() {
		genAt = time.Now().UTC()
	}

	var rows strings.Builder
	for _, f := range rep.Findings {
		sev := strings.ToLower(string(f.Severity))
		searchBlob := strings.ToLower(f.RuleID + " " + sev + " " + f.Title + " " + f.Target + " " + f.Description)
		fmt.Fprintf(&rows,
			`<tr data-severity="%s" data-search="%s">`+
				`<td><span class="pill sev-%s">%s</span></td>`+
				`<td><code>%s</code></td>`+
				`<td>%s</td>`+
				`<td><code>%s</code></td>`+
				`<td><strong>%s</strong><div class="desc">%s</div><div class="rem">Remediation: %s</div></td>`+
				`<td><code>%s</code></td>`+
				`<td><code>%s</code></td>`+
				`</tr>`+"\n",
			html.EscapeString(sev),
			html.EscapeString(searchBlob),
			html.EscapeString(sev),
			html.EscapeString(strings.ToUpper(sev)),
			html.EscapeString(f.RuleID),
			html.EscapeString(f.Module),
			html.EscapeString(f.Target),
			html.EscapeString(f.Title),
			html.EscapeString(f.Description),
			html.EscapeString(f.Remediation),
			html.EscapeString(f.MitreD3FEND),
			html.EscapeString(f.Timestamp.UTC().Format(time.RFC3339)),
		)
	}
	if len(rep.Findings) == 0 {
		rows.WriteString(`<tr><td colspan="7" class="empty">No correlated SIEM security incidents detected.</td></tr>`)
	}

	svgGraph := buildAttackGraphSVG(rep.Findings)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Raksa SIEM v%s Triage Report</title>
<style>
:root{--bg:#0b1220;--panel:#111a2e;--border:#23314d;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#3b82f6;--info:#64748b;--ok:#22c55e}
*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.45}
.wrap{max-width:1280px;margin:0 auto}
.header{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:16px;padding:20px;background:var(--panel);border:1px solid var(--border);border-radius:12px;margin-bottom:20px}
.title{font-size:1.35rem;font-weight:700}.sub{color:var(--muted);font-size:0.9rem;margin-top:4px}
.score-box{display:flex;align-items:center;gap:12px;padding:10px 18px;border:1px solid var(--border);border-radius:10px;background:#0f172a}
.score-num{font-size:1.8rem;font-weight:800;color:var(--accent)}.grade{padding:4px 10px;border-radius:999px;font-weight:700;background:#1e293b}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}.card .k{color:var(--muted);font-size:0.8rem;text-transform:uppercase}.card .v{font-size:1.5rem;font-weight:700;margin-top:4px}
.section{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:20px}
h2{margin:0 0 12px;font-size:1.05rem;color:#f8fafc}
.controls{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
input,select{background:#0f172a;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:0.9rem}
table{width:100%%;border-collapse:collapse;font-size:0.88rem}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-size:0.78rem;text-transform:uppercase;letter-spacing:0.04em}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-family:ui-monospace,Consolas,monospace;font-size:0.82rem}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:700;font-size:0.74rem}
.sev-critical{background:rgba(239,68,68,.2);color:#fca5a5}.sev-high{background:rgba(249,115,22,.2);color:#fdba74}.sev-medium{background:rgba(234,179,8,.2);color:#fde047}.sev-low{background:rgba(59,130,246,.2);color:#93c5fd}.sev-info{background:rgba(100,116,139,.2);color:#cbd5e1}
.desc{color:var(--muted);margin-top:4px;font-size:0.84rem}.rem{color:#a7f3d0;margin-top:4px;font-size:0.82rem}.empty{text-align:center;color:var(--ok);padding:24px}
svg{width:100%%;height:auto;background:#0f172a;border-radius:8px;border:1px solid var(--border)}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div>
      <div class="title">Raksa SIEM Security Triage Report (v%s)</div>
      <div class="sub">Layer: <code>%s</code> | Schema: <code>%s</code> | Generated: <code>%s</code></div>
    </div>
    <div class="score-box">
      <div><div class="sub">Posture Score</div><div class="score-num">%d/100</div></div>
      <div class="grade">%s</div>
    </div>
  </div>
  <div class="cards">
    <div class="card"><div class="k">Total</div><div class="v">%d</div></div>
    <div class="card"><div class="k">Critical</div><div class="v" style="color:var(--crit)">%d</div></div>
    <div class="card"><div class="k">High</div><div class="v" style="color:var(--high)">%d</div></div>
    <div class="card"><div class="k">Medium</div><div class="v" style="color:var(--med)">%d</div></div>
    <div class="card"><div class="k">Low</div><div class="v" style="color:var(--low)">%d</div></div>
  </div>
  <div class="section">
    <h2>Entity and Correlation Attack Graph</h2>
    %s
  </div>
  <div class="section">
    <h2>Correlated Incidents</h2>
    <div class="controls">
      <input id="q" type="search" placeholder="Filter by rule, host, IP, or text..." oninput="filterRows()">
      <select id="sev" onchange="filterRows()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Module</th><th>Target</th><th>Details</th><th>D3FEND</th><th>Timestamp</th></tr></thead>
      <tbody id="rows">%s</tbody>
    </table>
  </div>
</div>
<script>
function filterRows(){
  var q=(document.getElementById("q").value||"").toLowerCase();
  var s=(document.getElementById("sev").value||"").toLowerCase();
  var trs=document.querySelectorAll("#rows tr[data-severity]");
  for(var i=0;i<trs.length;i++){
    var rs=trs[i].getAttribute("data-severity")||"";
    var txt=trs[i].getAttribute("data-search")||"";
    var show=(!s||rs===s)&&(!q||txt.indexOf(q)!==-1);
    trs[i].style.display=show?"":"none";
  }
}
</script>
</body>
</html>
`,
		html.EscapeString(schema.Version),
		html.EscapeString(schema.Version),
		html.EscapeString(rep.Layer),
		html.EscapeString(rep.SchemaVersion),
		html.EscapeString(genAt.UTC().Format(time.RFC3339)),
		score,
		html.EscapeString(grade),
		rep.Summary.Total,
		rep.Summary.Critical,
		rep.Summary.High,
		rep.Summary.Medium,
		rep.Summary.Low,
		svgGraph,
		rows.String(),
	)
}

func buildAttackGraphSVG(findings []schema.Finding) string {
	if len(findings) == 0 {
		return `<svg viewBox="0 0 800 90" xmlns="http://www.w3.org/2000/svg"><text x="400" y="50" text-anchor="middle" fill="#22c55e" font-size="14">Clean Posture - Zero Correlation Edges</text></svg>`
	}

	var sources []string
	var rules []string
	var targets []string
	srcSeen := make(map[string]int)
	ruleSeen := make(map[string]int)
	tgtSeen := make(map[string]int)
	type edge struct{ src, rule, tgt int }
	var edges []edge

	capNodes := func(list *[]string, seen map[string]int, label string, limit int) int {
		if label == "" {
			label = "telemetry"
		}
		if idx, ok := seen[label]; ok {
			return idx
		}
		if len(*list) >= limit {
			return len(*list) - 1
		}
		idx := len(*list)
		*list = append(*list, label)
		seen[label] = idx
		return idx
	}

	for _, f := range findings {
		src := ""
		if f.Evidence != nil && f.Evidence["src_ip"] != nil {
			src = fmt.Sprint(f.Evidence["src_ip"])
		}
		if src == "" {
			src = f.Module
		}
		si := capNodes(&sources, srcSeen, src, 8)
		ri := capNodes(&rules, ruleSeen, f.RuleID, 8)
		ti := capNodes(&targets, tgtSeen, f.Target, 8)
		edges = append(edges, edge{src: si, rule: ri, tgt: ti})
	}

	maxRows := len(sources)
	if len(rules) > maxRows {
		maxRows = len(rules)
	}
	if len(targets) > maxRows {
		maxRows = len(targets)
	}
	height := 44*maxRows + 36
	if height < 140 {
		height = 140
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 920 %d" xmlns="http://www.w3.org/2000/svg">`, height)
	fmt.Fprintf(&b, `<text x="120" y="20" text-anchor="middle" fill="#94a3b8" font-size="11">SOURCES</text>`)
	fmt.Fprintf(&b, `<text x="460" y="20" text-anchor="middle" fill="#94a3b8" font-size="11">CORRELATION RULES</text>`)
	fmt.Fprintf(&b, `<text x="790" y="20" text-anchor="middle" fill="#94a3b8" font-size="11">TARGETS</text>`)

	yPos := func(idx int) int { return 46 + idx*40 }

	drawnEdge := make(map[string]bool)
	for _, e := range edges {
		k1 := fmt.Sprintf("sr-%d-%d", e.src, e.rule)
		if !drawnEdge[k1] {
			drawnEdge[k1] = true
			fmt.Fprintf(&b, `<line x1="210" y1="%d" x2="380" y2="%d" stroke="#38bdf8" stroke-opacity="0.45" stroke-width="1.5"/>`, yPos(e.src), yPos(e.rule))
		}
		k2 := fmt.Sprintf("rt-%d-%d", e.rule, e.tgt)
		if !drawnEdge[k2] {
			drawnEdge[k2] = true
			fmt.Fprintf(&b, `<line x1="540" y1="%d" x2="680" y2="%d" stroke="#f97316" stroke-opacity="0.5" stroke-width="1.5"/>`, yPos(e.rule), yPos(e.tgt))
		}
	}

	drawBox := func(x, y, w int, fill, stroke, label string) {
		short := label
		if len(short) > 24 {
			short = short[:21] + "..."
		}
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="26" rx="6" fill="%s" stroke="%s"/>`, x, y-13, w, fill, stroke)
		fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" fill="#e2e8f0" font-size="11" font-family="monospace">%s</text>`, x+w/2, y+4, html.EscapeString(short))
	}

	for i, s := range sources {
		drawBox(30, yPos(i), 180, "#172554", "#38bdf8", s)
	}
	for i, r := range rules {
		drawBox(380, yPos(i), 160, "#431407", "#f97316", r)
	}
	for i, t := range targets {
		drawBox(680, yPos(i), 210, "#1e293b", "#94a3b8", t)
	}
	b.WriteString(`</svg>`)
	return b.String()
}
