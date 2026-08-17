"""Professional, white-label assessment report renderer.

The renderer consumes normalized report JSON and produces deterministic HTML/PDF.
It intentionally treats tool output as untrusted display data and escapes all
values before rendering.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from weasyprint import HTML

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass(frozen=True)
class ReportBranding:
    organization_name: str = "Security Assessment"
    report_title: str = "Security Assessment Report"
    classification: str = "CONFIDENTIAL"
    logo_text: str = "NEXUS-STRIKE"
    accent: str = "#2463a6"
    footer: str = "Prepared by NEXUS-STRIKE"


def _text(value: Any, fallback: str = "—") -> str:
    value = str(value or "").strip()
    return escape(value) if value else fallback


def _severity(value: Any) -> str:
    value = str(value or "info").lower()
    return value if value in SEVERITIES else "info"


def _findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    raw = data.get("findings", [])
    normalized: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return normalized
    for item in raw:
        if not isinstance(item, dict):
            continue
        normalized.append({**item, "severity": _severity(item.get("severity"))})
    return sorted(
        normalized,
        key=lambda item: (-SEVERITY_WEIGHT[item["severity"]], _text(item.get("title"), "").lower()),
    )


def _risk_table(counts: dict[str, int]) -> str:
    return "".join(
        f"<tr><td class='sev sev-{severity}'>{severity.title()}</td><td>{counts.get(severity, 0)}</td></tr>"
        for severity in SEVERITIES
    )


def _finding_card(index: int, finding: dict[str, Any]) -> str:
    severity = finding["severity"]
    title = _text(finding.get("title") or finding.get("name"), "Untitled finding")
    description = _text(finding.get("description"), "No description supplied.")
    impact = _text(finding.get("impact"), "Impact should be validated against business context.")
    remediation = _text(finding.get("remediation") or finding.get("recommendation"), "Review vendor guidance and apply appropriate hardening.")
    asset = _text(finding.get("asset") or finding.get("target"))
    source = _text(finding.get("tool") or finding.get("source"))
    evidence = _text(finding.get("evidence"), "No evidence text supplied.")
    confidence = _text(finding.get("confidence"), "Unspecified")
    cve = _text(finding.get("cve"), "—")
    cwe = _text(finding.get("cwe"), "—")
    cvss = _text(finding.get("cvss"), "—")
    references = finding.get("references") or []
    refs = "".join(f"<li>{_text(item)}</li>" for item in references if item)
    reference_block = f"<h4>References</h4><ul>{refs}</ul>" if refs else ""
    return f"""
    <article class='finding'>
      <div class='finding-head'>
        <div><div class='finding-id'>F-{index:03d}</div><h3>{title}</h3></div>
        <span class='badge sev-{severity}'>{severity.upper()}</span>
      </div>
      <div class='meta-grid'>
        <div><span>Asset</span><strong>{asset}</strong></div>
        <div><span>Source</span><strong>{source}</strong></div>
        <div><span>Confidence</span><strong>{confidence}</strong></div>
        <div><span>CVSS</span><strong>{cvss}</strong></div>
        <div><span>CVE</span><strong>{cve}</strong></div>
        <div><span>CWE</span><strong>{cwe}</strong></div>
        <div><span>Validation</span><strong>Evidence-backed</strong></div>
        <div><span>Priority</span><strong>{'P0' if severity == 'critical' else 'P1' if severity == 'high' else 'P2' if severity == 'medium' else 'P3'}</strong></div>
      </div>
      <h4>Executive description</h4><p>{description}</p>
      <h4>Security / business impact</h4><p>{impact}</p>
      <h4>Evidence</h4><pre>{evidence}</pre>
      <h4>Recommended remediation</h4><p>{remediation}</p>
      {reference_block}
    </article>
    """


def render_html(data: dict[str, Any], branding: ReportBranding | None = None) -> str:
    branding = branding or ReportBranding()
    findings = _findings(data)
    counts = {severity: sum(item["severity"] == severity for item in findings) for severity in SEVERITIES}
    total = len(findings)
    meta = data.get("_meta", {}) if isinstance(data.get("_meta", {}), dict) else {}
    target = _text(meta.get("target") or data.get("target"))
    generated = _text(meta.get("generated_at") or data.get("timestamp"), "Not recorded")
    authorization = _text(meta.get("authorization_reference"), "Recorded in engagement controls")
    open_ports = data.get("open_ports", [])
    ports = ", ".join(str(p) for p in open_ports) if isinstance(open_ports, list) else _text(open_ports, "None recorded")
    weighted = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    risk_band = "Critical" if counts["critical"] else "High" if counts["high"] else "Moderate" if counts["medium"] else "Low"
    cards = "".join(_finding_card(i, f) for i, f in enumerate(findings, 1)) or "<div class='empty'>No findings were recorded for this assessment.</div>"

    css = """@page{size:A4;margin:18mm 16mm 20mm 16mm;@bottom-left{content:'__FOOTER__';font-size:8pt;color:#6b7280}@bottom-right{content:'Page ' counter(page) ' of ' counter(pages);font-size:8pt;color:#6b7280}}
*{box-sizing:border-box}body{margin:0;color:#17202b;font:10pt/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif}h1,h2,h3,h4{margin:0 0 8px}h2{font-size:17pt}h3{font-size:12pt}h4{font-size:9pt;color:#536273;text-transform:uppercase;letter-spacing:.08em;margin-top:14px}p{margin:0 0 8px}.cover{height:245mm;display:flex;flex-direction:column;justify-content:space-between;border-left:7px solid __ACCENT__}.brand{font-size:11pt;font-weight:750;letter-spacing:.1em;color:__ACCENT__}.cover-title{font-size:30pt;line-height:1.08;max-width:150mm;margin-top:22mm}.cover-meta{display:grid;grid-template-columns:1fr 1fr;gap:14px;border-top:1px solid #d9dee5;padding-top:12px}.meta-label{font-size:8pt;text-transform:uppercase;letter-spacing:.08em;color:#778394}.meta-value{font-weight:650;margin-top:2px}.classification{display:inline-block;border:1px solid #b8c1cc;padding:4px 8px;font-size:8pt;letter-spacing:.14em}.pagebreak{break-before:page}.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:12px 0 18px}.kpi{border:1px solid #dce1e7;padding:10px;background:#f8fafc}.kpi b{display:block;font-size:18pt}.section{margin-top:20px}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-bottom:1px solid #e4e7eb;text-align:left}th{font-size:8pt;text-transform:uppercase;letter-spacing:.07em;color:#687587}.sev{font-weight:700}.sev-critical{color:#a61b1b}.sev-high{color:#c2410c}.sev-medium{color:#9a6700}.sev-low{color:#1d5fa7}.sev-info{color:#526273}.badge{display:inline-block;padding:4px 8px;border:1px solid currentColor;font-size:8pt;font-weight:750;letter-spacing:.08em}.finding{break-inside:avoid;border:1px solid #dce1e7;padding:14px;margin:0 0 14px}.finding-head{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;border-bottom:1px solid #e8ebef;padding-bottom:9px}.finding-head h3{font-size:14pt}.finding-id{font-size:8pt;color:#788596;letter-spacing:.08em}.meta-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0}.meta-grid div{background:#f7f9fb;padding:8px}.meta-grid span{display:block;color:#7a8795;font-size:7.5pt;text-transform:uppercase}.meta-grid strong{display:block;margin-top:2px;font-size:8.5pt;overflow-wrap:anywhere}pre{background:#101820;color:#e6edf3;padding:10px;white-space:pre-wrap;font:8pt/1.45 'SFMono-Regular',Consolas,monospace;max-height:70mm;overflow:hidden}ul{padding-left:18px}.empty{padding:25px;text-align:center;color:#738094;border:1px dashed #cfd6de}.small{font-size:8pt;color:#657284}.toc td:last-child{text-align:right;color:#6b7684}"""
    css = css.replace("__FOOTER__", escape(branding.footer).replace("'", "\\'"))
    css = css.replace("__ACCENT__", escape(branding.accent))

    html = """<!doctype html><html><head><meta charset='utf-8'><title>__TITLE__</title><style>__CSS__</style></head><body>
<section class='cover'><div><div class='brand'>__LOGO__</div><h1 class='cover-title'>__TITLE__</h1><p class='small'>Professional security assessment deliverable</p></div>
<div class='cover-meta'><div><div class='meta-label'>Organization</div><div class='meta-value'>__ORG__</div></div><div><div class='meta-label'>Assessment target</div><div class='meta-value'>__TARGET__</div></div><div><div class='meta-label'>Authorization reference</div><div class='meta-value'>__AUTH__</div></div><div><div class='meta-label'>Generated</div><div class='meta-value'>__GENERATED__</div></div></div><div><span class='classification'>__CLASSIFICATION__</span></div></section>
<section class='pagebreak'><h2>Executive summary</h2><p>This report presents a normalized, evidence-backed summary of the assessment. Findings are ordered by severity and should be validated against business criticality before remediation commitments are finalized.</p>
<div class='summary-grid'><div class='kpi'><span class='small'>Total findings</span><b>__TOTAL__</b></div><div class='kpi'><span class='small'>Risk band</span><b>__RISK__</b></div><div class='kpi'><span class='small'>Weighted exposure</span><b>__WEIGHTED__</b></div><div class='kpi'><span class='small'>Open ports</span><b>__PORT_COUNT__</b></div></div>
<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>__RISK_TABLE__</tbody></table><div class='section'><h3>Assessment posture</h3><p>Prioritize critical and high-severity findings first, then address recurring medium-risk weaknesses and hardening opportunities. Retest resolved findings and retain the associated evidence for closure validation.</p></div></section>
<section class='pagebreak'><h2>Engagement scope &amp; methodology</h2><table><tbody><tr><th>Target</th><td>__TARGET__</td></tr><tr><th>Authorization</th><td>__AUTH__</td></tr><tr><th>Open services</th><td>__PORTS__</td></tr><tr><th>Evidence model</th><td>Normalized observations with preserved provenance</td></tr><tr><th>Finding model</th><td>Severity, confidence, asset, evidence and remediation</td></tr></tbody></table><div class='section'><h3>Professional handling notes</h3><p>Raw tool output is treated as untrusted data. Report content is generated deterministically from the assessment snapshot. AI-generated reasoning must not be represented as confirmed exploitation unless the underlying evidence supports that conclusion.</p></div></section>
<section class='pagebreak'><h2>Findings</h2><p class='small'>__TOTAL__ finding(s) included. Severity and confidence should be interpreted together with business criticality and validated attack paths.</p>__CARDS__</section>
<section class='pagebreak'><h2>Remediation roadmap</h2><table><thead><tr><th>Priority</th><th>Focus</th><th>Recommended outcome</th></tr></thead><tbody><tr><td class='sev-critical'>P0</td><td>Critical exposure</td><td>Contain immediately, validate exploitability, patch or remove exposure, then retest.</td></tr><tr><td class='sev-high'>P1</td><td>High-risk weaknesses</td><td>Remediate rapidly, reduce external exposure and confirm controls with targeted retesting.</td></tr><tr><td class='sev-medium'>P2</td><td>Medium findings</td><td>Bundle by root cause and establish engineering remediation owners.</td></tr><tr><td class='sev-low'>P3</td><td>Hardening</td><td>Address during routine security engineering and configuration baselines.</td></tr></tbody></table></section>
<section class='pagebreak'><h2>Appendix</h2><h3>Evidence and provenance</h3><p>Mission, tool, agent and report versions should be retained alongside the source assessment snapshot. Evidence references in this report are intended to support reproducibility and retesting.</p><h3>Classification</h3><p class='small'>This document should be handled according to the engagement's information-classification policy. Do not distribute outside authorized recipients.</p></section></body></html>"""
    values = {
        "__CSS__": css,
        "__TITLE__": _text(branding.report_title),
        "__LOGO__": _text(branding.logo_text),
        "__ORG__": _text(branding.organization_name),
        "__TARGET__": target,
        "__AUTH__": authorization,
        "__GENERATED__": generated,
        "__CLASSIFICATION__": _text(branding.classification),
        "__TOTAL__": str(total),
        "__RISK__": risk_band,
        "__WEIGHTED__": str(weighted),
        "__PORT_COUNT__": str(len(open_ports) if isinstance(open_ports, list) else "—"),
        "__PORTS__": _text(ports, "None recorded"),
        "__RISK_TABLE__": _risk_table(counts),
        "__CARDS__": cards,
    }
    for marker, value in values.items():
        html = html.replace(marker, value)
    return html


def render_pdf(data: dict[str, Any], output: str | Path, branding: ReportBranding | None = None) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=render_html(data, branding), base_url=str(output_path.parent)).write_pdf(str(output_path))
    return output_path
