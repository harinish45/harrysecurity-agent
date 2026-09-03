#!/usr/bin/env python3
"""
NEXUS-STRIKE Report Viewer
A minimal FastAPI server that renders mission reports as beautiful HTML pages.
Run: python scripts/serve_reports.py
Then open: http://localhost:8000
"""
import re
import sys
from pathlib import Path

# ── ensure project root is on the path ──────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

REPORTS_DIR = ROOT / "reports"

app = FastAPI(title="NEXUS-STRIKE Report Viewer", docs_url=None, redoc_url=None)

# ── tiny markdown → HTML converter (no external deps) ───────────────────────
def md_to_html(md: str) -> str:
    lines = md.splitlines()
    html_lines = []
    in_table = False

    for raw in lines:
        line = raw.rstrip()

        # Headings
        if line.startswith("### "):
            html_lines.append(f'<h3>{_inline(line[4:])}</h3>')
            continue
        if line.startswith("## "):
            html_lines.append(f'<h2>{_inline(line[3:])}</h2>')
            continue
        if line.startswith("# "):
            html_lines.append(f'<h1>{_inline(line[2:])}</h1>')
            continue

        # Tables
        if "|" in line and line.strip().startswith("|"):
            if "---" in line:
                continue  # separator row
            if not in_table:
                html_lines.append('<table>')
                in_table = True
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            tag = "th" if not any(c.startswith("**Title") for c in cells) else "td"
            row = "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")
            continue
        else:
            if in_table:
                html_lines.append("</table>")
                in_table = False

        # Horizontal rule
        if line.strip().startswith("---"):
            html_lines.append("<hr>")
            continue

        # List items
        if line.startswith("- "):
            html_lines.append(f'<li>{_inline(line[2:])}</li>')
            continue

        # Bold key: value pattern (finding fields)
        if line.startswith("**") and ":**" in line:
            html_lines.append(f'<p class="meta">{_inline(line)}</p>')
            continue

        # Empty line
        if not line.strip():
            html_lines.append("<br>")
            continue

        html_lines.append(f"<p>{_inline(line)}</p>")

    if in_table:
        html_lines.append("</table>")

    return "\n".join(html_lines)


def _inline(text: str) -> str:
    """Apply inline markdown: bold, code, links."""
    # Escape HTML first
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # Inline code
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    # Severity badges
    for sev, cls in [("CRITICAL","crit"),("HIGH","high"),("MEDIUM","med"),("LOW","low"),("INFO","info")]:
        text = text.replace(sev, f'<span class="badge {cls}">{sev}</span>')
    # Emojis passthrough (they're already Unicode)
    return text


def _severity_badge(content: str) -> str:
    """Return a CSS class based on finding content."""
    if "CRITICAL" in content: return "finding-crit"
    if "HIGH" in content:     return "finding-high"
    if "MEDIUM" in content:   return "finding-med"
    if "LOW" in content:      return "finding-low"
    if "WARN" in content:     return "finding-warn"
    return "finding-info"


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEXUS-STRIKE | {title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

  :root {{
    --bg:       #0a0d14;
    --surface:  #111520;
    --border:   #1e2535;
    --accent:   #00d4ff;
    --accent2:  #7c3aed;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --crit:     #ef4444;
    --high:     #f97316;
    --med:      #eab308;
    --low:      #3b82f6;
    --info:     #64748b;
    --success:  #10b981;
    --warn:     #f59e0b;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    line-height: 1.7;
    min-height: 100vh;
  }}

  /* ── Top bar ── */
  .topbar {{
    background: linear-gradient(90deg, #0a0d14 0%, #111520 50%, #0a0d14 100%);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 56px;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(10px);
  }}
  .topbar .logo {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1rem;
    font-weight: 600;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: 1px;
  }}
  .topbar nav a {{
    color: var(--muted);
    text-decoration: none;
    margin-left: 1.5rem;
    font-size: 0.85rem;
    transition: color .2s;
  }}
  .topbar nav a:hover {{ color: var(--accent); }}
  .topbar nav a.active {{ color: var(--accent); }}

  /* ── Layout ── */
  .container {{
    max-width: 1100px;
    margin: 0 auto;
    padding: 2.5rem 1.5rem;
  }}

  /* ── Report index ── */
  .report-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1rem;
    margin-top: 1.5rem;
  }}
  .report-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    text-decoration: none;
    color: var(--text);
    transition: border-color .2s, transform .2s, box-shadow .2s;
    display: block;
  }}
  .report-card:hover {{
    border-color: var(--accent);
    transform: translateY(-2px);
    box-shadow: 0 8px 30px rgba(0,212,255,.08);
  }}
  .report-card .rc-title {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem;
    color: var(--accent);
    margin-bottom: .5rem;
  }}
  .report-card .rc-meta {{ color: var(--muted); font-size: 0.8rem; }}

  /* ── Hero banner ── */
  .report-hero {{
    background: linear-gradient(135deg, #111520 0%, #0f172a 100%);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2rem 2.5rem;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
  }}
  .report-hero::before {{
    content: '';
    position: absolute;
    top: -60px; right: -60px;
    width: 200px; height: 200px;
    background: radial-gradient(circle, rgba(0,212,255,.08) 0%, transparent 70%);
    border-radius: 50%;
  }}
  .report-hero h1 {{
    font-size: 1.6rem;
    font-weight: 700;
    margin-bottom: 0.3rem;
    background: linear-gradient(135deg, var(--accent), #fff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }}
  .report-hero .target {{
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent);
    font-size: 0.9rem;
  }}
  .report-hero .meta-row {{
    display: flex;
    gap: 2rem;
    margin-top: 1rem;
    flex-wrap: wrap;
  }}
  .report-hero .meta-item {{
    display: flex;
    flex-direction: column;
    gap: .2rem;
  }}
  .report-hero .meta-label {{
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: .05em;
    color: var(--muted);
  }}
  .report-hero .meta-value {{
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--text);
  }}

  /* ── Stats row ── */
  .stats-row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1rem;
    text-align: center;
  }}
  .stat-card .stat-num {{
    font-size: 2rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
  }}
  .stat-card .stat-label {{
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: .05em;
    color: var(--muted);
    margin-top: .4rem;
  }}
  .stat-card.crit .stat-num {{ color: var(--crit); }}
  .stat-card.high .stat-num {{ color: var(--high); }}
  .stat-card.med  .stat-num {{ color: var(--med); }}
  .stat-card.low  .stat-num {{ color: var(--low); }}
  .stat-card.info .stat-num {{ color: var(--muted); }}
  .stat-card.total .stat-num {{ color: var(--accent); }}

  /* ── Section headers ── */
  .section-header {{
    display: flex;
    align-items: center;
    gap: .75rem;
    margin: 2rem 0 1rem;
    padding-bottom: .75rem;
    border-bottom: 1px solid var(--border);
  }}
  .section-header h2 {{
    font-size: 1rem;
    font-weight: 600;
    color: var(--text);
    text-transform: uppercase;
    letter-spacing: .08em;
  }}
  .section-header .dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
  }}

  /* ── Finding cards ── */
  .findings-list {{ display: flex; flex-direction: column; gap: .75rem; }}
  .finding {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--info);
    border-radius: 10px;
    padding: 1rem 1.25rem;
    transition: border-color .2s, box-shadow .2s;
  }}
  .finding:hover {{
    box-shadow: 0 4px 20px rgba(0,0,0,.3);
  }}
  .finding.finding-crit {{ border-left-color: var(--crit); }}
  .finding.finding-high {{ border-left-color: var(--high); }}
  .finding.finding-med  {{ border-left-color: var(--med); }}
  .finding.finding-low  {{ border-left-color: var(--low); }}
  .finding.finding-warn {{ border-left-color: var(--warn); }}
  .finding.finding-info {{ border-left-color: var(--muted); }}

  .finding-title {{
    font-size: 0.88rem;
    font-weight: 500;
    color: var(--text);
    margin-bottom: .4rem;
    font-family: 'JetBrains Mono', monospace;
    word-break: break-all;
  }}
  .finding-meta {{
    display: flex;
    gap: .75rem;
    flex-wrap: wrap;
    align-items: center;
    font-size: 0.75rem;
    color: var(--muted);
  }}
  .finding-tool {{
    background: rgba(0,212,255,.08);
    color: var(--accent);
    padding: .15rem .5rem;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
  }}

  /* ── Badges ── */
  .badge {{
    display: inline-block;
    padding: .1rem .45rem;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: .03em;
  }}
  .badge.crit {{ background: rgba(239,68,68,.15);  color: var(--crit); }}
  .badge.high {{ background: rgba(249,115,22,.15); color: var(--high); }}
  .badge.med  {{ background: rgba(234,179,8,.15);  color: var(--med); }}
  .badge.low  {{ background: rgba(59,130,246,.15); color: var(--low); }}
  .badge.info {{ background: rgba(100,116,139,.15);color: var(--muted); }}

  /* ── Empty state ── */
  .empty {{
    text-align: center;
    padding: 4rem 2rem;
    color: var(--muted);
  }}
  .empty h2 {{ font-size: 1.2rem; margin-bottom: .5rem; color: var(--text); }}

  /* ── General prose elements ── */
  h1,h2,h3 {{ color: var(--text); margin: 1rem 0 .5rem; }}
  h1 {{ font-size: 1.6rem; }}
  h2 {{ font-size: 1.2rem; }}
  h3 {{ font-size: 1rem; }}
  p   {{ margin: .3rem 0; color: var(--text); }}
  p.meta {{ color: var(--muted); font-size: 0.82rem; }}
  li  {{ margin-left: 1.5rem; color: var(--text); }}
  code {{
    font-family: 'JetBrains Mono', monospace;
    background: rgba(0,212,255,.06);
    color: var(--accent);
    padding: .1rem .35rem;
    border-radius: 3px;
    font-size: 0.85em;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    font-size: 0.84rem;
  }}
  th,td {{
    border: 1px solid var(--border);
    padding: .5rem .75rem;
    text-align: left;
  }}
  th {{ background: rgba(0,212,255,.05); color: var(--accent); font-size: .75rem; text-transform: uppercase; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}
  hr {{ border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }}
  br {{ display: block; margin: .15rem 0; }}
  strong {{ color: var(--text); font-weight: 600; }}
</style>
</head>
<body>
<div class="topbar">
  <span class="logo">⚡ NEXUS-STRIKE</span>
  <nav>
    <a href="/" class="{home_active}">Reports</a>
  </nav>
</div>
<div class="container">
{body}
</div>
</body>
</html>"""


def parse_report(md: str) -> dict:
    """Parse key fields out of the markdown report."""
    info = {"target": "Unknown", "mission": "Unknown", "generated": "Unknown",
            "findings_total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info_count": 0}

    for line in md.splitlines():
        if "**Mission:**" in line:
            m = re.search(r'`(.+?)`', line)
            if m: info["mission"] = m.group(1)
        elif "**Target:**" in line:
            m = re.search(r'`(.+?)`', line)
            if m: info["target"] = m.group(1)
        elif "**Generated:**" in line:
            info["generated"] = line.split("**Generated:**")[-1].strip()
        elif "recorded **" in line:
            m = re.search(r'recorded \*\*(\d+)\*\*', line)
            if m: info["findings_total"] = int(m.group(1))
        elif "🔴 **CRITICAL**" in line:
            m = re.search(r'\((\d+)\)', line)
            if m: info["critical"] = int(m.group(1))
        elif "🟠 **HIGH**" in line:
            m = re.search(r'\((\d+)\)', line)
            if m: info["high"] = int(m.group(1))
        elif "🟡 **MEDIUM**" in line:
            m = re.search(r'\((\d+)\)', line)
            if m: info["medium"] = int(m.group(1))
        elif "🔵 **LOW**" in line:
            m = re.search(r'\((\d+)\)', line)
            if m: info["low"] = int(m.group(1))
        elif "⚪ **INFO**" in line:
            m = re.search(r'\((\d+)\)', line)
            if m: info["info_count"] = int(m.group(1))
    return info


def extract_findings(md: str) -> list:
    """Extract individual findings as dicts."""
    findings = []
    current = {}
    for line in md.splitlines():
        line = line.strip()
        if line.startswith("### "):
            if current:
                findings.append(current)
            current = {"sev": "INFO", "title": "", "tool": "", "asset": ""}
        elif "**Title:**" in line:
            current["title"] = line.split("**Title:**")[-1].strip()
        elif "**Severity:**" in line:
            m = re.search(r'\*\*Severity:\*\* (\w+)', line)
            if m: current["sev"] = m.group(1)
        elif "**Tool:**" in line:
            current["tool"] = line.split("**Tool:**")[-1].strip()
        elif "**Affected asset:**" in line:
            current["asset"] = line.split("**Affected asset:**")[-1].strip()
    if current and current.get("title"):
        findings.append(current)
    return [f for f in findings if f.get("title")]


@app.get("/", response_class=HTMLResponse)
def index():
    reports = sorted(REPORTS_DIR.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        body = '<div class="empty"><h2>No reports yet</h2><p>Run <code>nexus run --target ...</code> to generate one.</p></div>'
    else:
        cards = ""
        for rp in reports:
            md = rp.read_text(encoding="utf-8", errors="replace")
            info = parse_report(md)
            cards += f"""
            <a class="report-card" href="/report/{rp.name}">
              <div class="rc-title">📄 {rp.stem}</div>
              <div class="rc-meta">🎯 {info['target']} &nbsp;|&nbsp; 🕒 {info['generated']}</div>
              <div class="rc-meta" style="margin-top:.3rem">
                Findings: <strong style="color:var(--accent)">{info['findings_total']}</strong>
                &nbsp;·&nbsp; CRIT: <span style="color:var(--crit)">{info['critical']}</span>
                &nbsp;·&nbsp; HIGH: <span style="color:var(--high)">{info['high']}</span>
              </div>
            </a>"""
        body = f'<h1 style="margin-bottom:.3rem">Mission Reports</h1><p style="color:var(--muted)">{len(reports)} report(s) found</p><div class="report-grid">{cards}</div>'

    return PAGE_TEMPLATE.format(title="Reports", home_active="active", body=body)


@app.get("/report/{filename}", response_class=HTMLResponse)
def view_report(filename: str):
    rp = REPORTS_DIR / filename
    if not rp.exists() or not filename.endswith(".md"):
        raise HTTPException(status_code=404, detail="Report not found")

    md = rp.read_text(encoding="utf-8", errors="replace")
    info = parse_report(md)
    findings = extract_findings(md)

    # Hero
    hero = f"""
    <div class="report-hero">
      <h1>Security Assessment Report</h1>
      <div class="target">🎯 {html.escape(str(info['target']))}</div>
      <div class="meta-row">
        <div class="meta-item"><span class="meta-label">Mission</span><span class="meta-value">{html.escape(str(info['mission']))}</span></div>
        <div class="meta-item"><span class="meta-label">Generated</span><span class="meta-value">{html.escape(str(info['generated']))}</span></div>
        <div class="meta-item"><span class="meta-label">LLM Provider</span><span class="meta-value">Groq / Llama 3.1</span></div>
      </div>
    </div>"""

    # Stats
    stats = f"""
    <div class="stats-row">
      <div class="stat-card total"><div class="stat-num">{html.escape(str(info['findings_total']))}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card crit"><div class="stat-num">{html.escape(str(info['critical']))}</div><div class="stat-label">Critical</div></div>
      <div class="stat-card high"><div class="stat-num">{html.escape(str(info['high']))}</div><div class="stat-label">High</div></div>
      <div class="stat-card med"><div class="stat-num">{html.escape(str(info['medium']))}</div><div class="stat-label">Medium</div></div>
      <div class="stat-card low"><div class="stat-num">{html.escape(str(info['low']))}</div><div class="stat-label">Low</div></div>
      <div class="stat-card info"><div class="stat-num">{html.escape(str(info['info_count']))}</div><div class="stat-label">Info</div></div>
    </div>"""

    # Findings
    sev_class = {"CRITICAL":"finding-crit","HIGH":"finding-high","MEDIUM":"finding-med","LOW":"finding-low","INFO":"finding-info"}
    finding_html = ""
    warn_count = 0
    for f in findings:
        fc = "finding-warn" if f["title"].startswith("WARN") else sev_class.get(f["sev"], "finding-info")
        if f["title"].startswith("WARN"):
            warn_count += 1
        finding_html += f"""
        <div class="finding {fc}">
          <div class="finding-title">{html.escape(str(f['title']))}</div>
          <div class="finding-meta">
            <span class="badge {f['sev'].lower()}">{html.escape(str(f['sev']))}</span>
            <span class="finding-tool">{html.escape(str(f['tool']))}</span>
            <span>{html.escape(str(f['asset']))}</span>
          </div>
        </div>"""

    findings_section = f"""
    <div class="section-header"><div class="dot"></div><h2>Findings ({len(findings)})</h2></div>
    <div class="findings-list">{finding_html}</div>"""

    body = hero + stats + findings_section
    return PAGE_TEMPLATE.format(title=f"Report — {info['target']}", home_active="", body=body)


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print("\n  NEXUS-STRIKE Report Viewer")
    print(f"  Reports from: {REPORTS_DIR}")
    print("  Open: http://localhost:8000\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
