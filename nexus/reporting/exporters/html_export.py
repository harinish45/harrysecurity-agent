"""Branded HTML export — uses the canonical Finding schema."""
from __future__ import annotations

import logging
from html import escape
from pathlib import Path
from typing import Any

from nexus.foundation.schema import normalize_findings, redact_findings

logger = logging.getLogger("nexus.reporting")


class HtmlExport:
    """Export a self-contained, branded HTML findings report."""

    FINDING_FIELDS = [
        "id", "title", "severity", "confidence", "affected_asset",
        "evidence", "remediation", "references", "timestamp", "tool",
    ]

    def export(
        self,
        data: list[Any],
        output: str | Path,
        title: str = "NEXUS-STRIKE Security Assessment Report",
        redact: bool = True,
        include_visualizations: bool = True,
    ) -> Path:
        findings = normalize_findings(data)
        if redact:
            findings = redact_findings(findings)
        rows = self._build_rows(findings)
        summary = self._build_summary(findings)
        visualizations = self._build_visualizations(findings) if include_visualizations else ""
        chains = self._build_chains(findings)
        document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title>
<style>
  :root {{
    --bg:#f5f6fa; --surface:#fff; --text:#172033; --text-dim:#5e6c84; --border:#eef2f8;
    --code-bg:#f8f9fc; --viz-bg:#0a0d14; --viz-text:#e2e8f0;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg:#0b0f19; --surface:#131a2b; --text:#e6eaf2; --text-dim:#8b96ab; --border:#232d42;
      --code-bg:#0e1524; --viz-bg:#05070c; --viz-text:#e2e8f0;
    }}
  }}
  :root[data-theme="dark"] {{
    --bg:#0b0f19; --surface:#131a2b; --text:#e6eaf2; --text-dim:#8b96ab; --border:#232d42;
    --code-bg:#0e1524; --viz-bg:#05070c; --viz-text:#e2e8f0;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:system-ui,-apple-system,'Segoe UI',sans-serif; background:var(--bg); color:var(--text); padding:2rem }}
  .container {{ max-width:1100px; margin:0 auto }}
  h1 {{ font-size:1.75rem; margin-bottom:.25rem; color:var(--text) }}
  .subtitle {{ color:var(--text-dim); margin-bottom:1rem; font-size:.9rem }}
  .filter-bar {{ position:sticky; top:0; z-index:5; display:flex; gap:.4rem; flex-wrap:wrap; background:var(--bg);
                padding:.75rem 0; margin-bottom:1rem; border-bottom:1px solid var(--border) }}
  .filter-btn {{ font-size:.75rem; font-weight:600; padding:4px 12px; border-radius:12px; border:1px solid var(--border);
                background:var(--surface); color:var(--text-dim); cursor:pointer }}
  .filter-btn.active {{ background:var(--text); color:var(--bg) }}
  .summary-cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin-bottom:2rem }}
  .card {{ background:var(--surface); border-radius:8px; padding:1.25rem; box-shadow:0 1px 3px rgba(0,0,0,.08) }}
  .card .count {{ font-size:2rem; font-weight:700 }}
  .card .label {{ font-size:.8rem; color:var(--text-dim); text-transform:uppercase; letter-spacing:.5px }}
  .critical .count {{ color:#e5484d }} .high .count {{ color:#f0883e }}
  .medium .count {{ color:#dc6803 }} .low .count {{ color:#3b82f6 }} .info .count {{ color:var(--text-dim) }}
  .visualizations {{ display:flex; flex-direction:column; gap:1.25rem; margin-bottom:2rem }}
  .viz-block {{ background:var(--viz-bg); border-radius:8px; padding:1rem; box-shadow:0 1px 3px rgba(0,0,0,.08) }}
  .viz-block h2 {{ color:var(--viz-text); font-size:.85rem; text-transform:uppercase; letter-spacing:.5px; margin-bottom:.75rem }}
  .viz-block svg {{ width:100%; height:auto; display:block }}
  table {{ width:100%; border-collapse:separate; border-spacing:0; background:var(--surface); border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.08) }}
  th,td {{ padding:.75rem 1rem; text-align:left; vertical-align:top; border-bottom:1px solid var(--border) }}
  th {{ background:var(--code-bg); font-weight:600; font-size:.8rem; text-transform:uppercase; letter-spacing:.5px; color:var(--text-dim) }}
  tr:last-child td {{ border-bottom:none }}
  .sev-critical,.sev-high {{ color:#e5484d; font-weight:600 }}
  .sev-medium {{ color:#dc6803; font-weight:600 }}
  .sev-low {{ color:#3b82f6; font-weight:600 }}
  .sev-info {{ color:var(--text-dim) }}
  .evidence {{ font-family:'SF Mono','Cascadia Code','Fira Code',monospace; font-size:.8rem; background:var(--code-bg); padding:.5rem; border-radius:4px; white-space:pre-wrap; max-height:120px; overflow-y:auto }}
  .tag {{ display:inline-block; font-size:.7rem; padding:2px 8px; border-radius:10px; font-weight:600 }}
  .tag-critical {{ background:#3b0d0f; color:#ff6369 }} .tag-high {{ background:#3a2308; color:#f0883e }}
  .tag-medium {{ background:#3a2a08; color:#dc6803 }} .tag-low {{ background:#0c2340; color:#5b9dff }}
  .tag-info {{ background:var(--code-bg); color:var(--text-dim) }}
  .badge {{ display:inline-block; font-size:.65rem; font-weight:700; padding:1px 7px; border-radius:8px; margin-right:4px;
           text-transform:uppercase; letter-spacing:.3px }}
  .badge-verified {{ background:#0b3a1f; color:#4ade80 }}
  .badge-unverified {{ background:#3a2a08; color:#facc15 }}
  .badge-failed {{ background:#3b0d0f; color:#ff6369 }}
  .badge-non_replayable {{ background:var(--code-bg); color:var(--text-dim) }}
  .badge-likely_false_positive {{ background:#3a1a08; color:#fb923c }}
  .mitre-chip {{ display:inline-block; font-size:.65rem; padding:1px 6px; border-radius:6px; margin:1px 2px 1px 0;
               background:#0c2340; color:#5b9dff; text-decoration:none }}
  .impact {{ font-size:.75rem; color:var(--text-dim); margin-top:.25rem }}
  .chains {{ margin-bottom:1.5rem }}
  .chains summary {{ cursor:pointer; font-weight:600; padding:.75rem 1rem; background:var(--surface);
                     border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,.08); list-style:none }}
  .chains summary::-webkit-details-marker {{ display:none }}
  .chains summary::before {{ content:'\\25B8'; display:inline-block; margin-right:.5rem; transition:transform .15s }}
  .chains[open] summary::before {{ transform:rotate(90deg) }}
  .chain-list {{ background:var(--surface); border-radius:0 0 8px 8px; padding:.5rem 1rem 1rem; margin-top:-4px }}
  .chain-item {{ padding:.5rem 0; border-bottom:1px solid var(--border); font-size:.85rem }}
  .chain-item:last-child {{ border-bottom:none }}
  .chain-path {{ font-family:'SF Mono','Cascadia Code','Fira Code',monospace; color:var(--text-dim) }}
  .footer {{ margin-top:2rem; font-size:.8rem; color:var(--text-dim); text-align:center }}
</style>
</head>
<body>
<div class="container">
  <h1>{escape(title)}</h1>
  <p class="subtitle">Generated by NEXUS-STRIKE &mdash; {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &mdash; {len(findings)} findings</p>

  {summary}

  {visualizations}

  {chains}

  <div class="filter-bar" id="sevFilterBar">
    <button class="filter-btn active" data-sev="all">All</button>
    <button class="filter-btn" data-sev="critical">Critical</button>
    <button class="filter-btn" data-sev="high">High</button>
    <button class="filter-btn" data-sev="medium">Medium</button>
    <button class="filter-btn" data-sev="low">Low</button>
    <button class="filter-btn" data-sev="info">Info</button>
  </div>

  <table>
    <thead><tr>
      <th>ID</th><th>Severity</th><th>Title</th><th>Asset</th><th>Evidence</th><th>Remediation</th>
    </tr></thead>
    <tbody id="findingsBody">{rows}</tbody>
  </table>

  <p class="footer">NEXUS-STRIKE Security Assessment &mdash; Validate findings before remediation.</p>
</div>
<script>
  document.getElementById('sevFilterBar').addEventListener('click', function (e) {{
    var btn = e.target.closest('.filter-btn');
    if (!btn) return;
    document.querySelectorAll('#sevFilterBar .filter-btn').forEach(function (b) {{ b.classList.remove('active'); }});
    btn.classList.add('active');
    var sev = btn.getAttribute('data-sev');
    document.querySelectorAll('#findingsBody tr').forEach(function (row) {{
      row.hidden = sev !== 'all' && row.getAttribute('data-sev') !== sev;
    }});
  }});
</script>
</body>
</html>"""
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(document, encoding="utf-8")
        return path

    def _build_visualizations(self, findings: list[dict]) -> str:
        from nexus.reporting.visualizations.attack_graph_viz import AttackGraphViz
        from nexus.reporting.visualizations.risk_heatmap import RiskHeatmap
        from nexus.reporting.visualizations.timeline_viz import TimelineViz

        blocks = []
        for label, viz in (
            ("Attack Graph", AttackGraphViz()),
            ("Risk Heatmap", RiskHeatmap()),
            ("Finding Timeline", TimelineViz()),
        ):
            try:
                svg = viz.render(findings)
            except Exception:
                logger.warning("visualization %r failed to render; skipping", label, exc_info=True)
                continue
            if svg:
                blocks.append(f'<div class="viz-block"><h2>{escape(label)}</h2>{svg}</div>')

        if not blocks:
            return ""
        return f'<section class="visualizations">{"".join(blocks)}</section>'

    def _build_chains(self, findings: list[dict]) -> str:
        """Collapsible view of attack_chain_agent's synthetic chain findings
        (multi-hop compositions across findings, e.g. "this cred unlocks that
        host") — rendered separately from the flat findings table since a
        chain isn't a single observation, it's a claim about several."""
        chains = [f for f in findings if f.get("kind") == "synthetic_chain"]
        if not chains:
            return ""
        items = []
        for c in chains:
            sev = c.get("severity", "info")
            path = " &rarr; ".join(escape(a) for a in (c.get("chain_assets") or []))
            items.append(
                f'<div class="chain-item">'
                f'<span class="tag tag-{sev}">{sev.upper()}</span> '
                f'<strong>{escape(c.get("id", ""))}</strong> &mdash; {escape(c.get("title", ""))}'
                f'<div class="chain-path">{path}</div>'
                f'</div>'
            )
        return (
            f'<details class="chains" open>'
            f'<summary>Attack chains ({len(chains)})</summary>'
            f'<div class="chain-list">{"".join(items)}</div>'
            f'</details>'
        )

    def _build_summary(self, findings: list[dict]) -> str:
        from collections import Counter
        counts = Counter(f.get("severity", "info") for f in findings)
        sevs = ["critical", "high", "medium", "low", "info"]
        cards = "\n".join(
            f'<div class="card {s}"><div class="count">{counts.get(s, 0)}</div><div class="label">{s}</div></div>'
            for s in sevs
        )
        return f'<div class="summary-cards">{cards}</div>'

    def _build_rows(self, findings: list[dict]) -> str:
        if not findings:
            return '<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-dim)">No findings recorded.</td></tr>'
        rows = []
        for f in findings:
            sev = f.get("severity", "info")
            verification = f.get("verification_status")
            verification_badge = (
                f'<span class="badge badge-{verification}" title="{escape(f.get("verification_detail", ""))}">'
                f'{verification.replace("_", " ")}</span>'
                if verification else ""
            )
            mitre_chips = "".join(
                f'<a class="mitre-chip" href="{escape(t.get("url", "#"))}" target="_blank" rel="noopener">{escape(t.get("id", ""))}</a>'
                for t in (f.get("mitre_techniques") or [])
            )
            impact = f.get("business_impact")
            impact_html = f'<div class="impact">{escape(impact)}</div>' if impact else ""
            rows.append(
                f'<tr data-sev="{sev}">'
                f'<td><strong>{escape(f.get("id", ""))}</strong></td>'
                f'<td class="sev-{sev}"><span class="tag tag-{sev}">{sev.upper()}</span></td>'
                f'<td>{verification_badge}{escape(f.get("title", ""))}<br>'
                f'<small style="color:var(--text-dim)">{escape(f.get("tool", ""))}</small>'
                f'{" " + mitre_chips if mitre_chips else ""}{impact_html}</td>'
                f'<td>{escape(f.get("affected_asset", ""))}</td>'
                f'<td><div class="evidence">{escape(f.get("evidence", ""))}</div></td>'
                f'<td>{escape(f.get("remediation", ""))}</td>'
                f'</tr>'
            )
        return "\n".join(rows)