#!/usr/bin/env python3
"""
NEXUS-STRIKE — PurpleSec-style PDF Report Generator (v2)
====================================================
Takes a raw JSON file from scripts/nexus_scan.py and produces a 16-page
professional vulnerability assessment PDF report.

Usage:
    python scripts/nexus_report.py reports/<target>_<timestamp>.json
    python scripts/nexus_report.py reports/latest.json --output report.pdf
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

REPORTS_DIR = Path(_PROJECT_ROOT) / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 465, 587, 631, 993, 995, 1433, 1521, 3000,
    3306, 3389, 4000, 5000, 5432, 5900, 6379, 7070, 8000, 8080,
    8443, 8888, 9000, 9090, 9200, 27017, 27018, 50000,
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e74c3c",
    "medium": "#f39c12",
    "low": "#3498db",
    "info": "#95a5a6",
}

HIGH_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017}
MEDIUM_PORTS = {22, 25, 53, 110, 143, 993, 995, 8443}
# Development/admin ports — these are LOW risk because they are commonly
# run by developers locally and rarely represent production exposure.
LOW_PORTS = {80, 443, 8080, 8000, 3000, 5000, 8888, 9000, 9090, 4000, 7070}


# ---------------------------------------------------------------------------
# Issue 1 + Issue 2: Real prose generation for descriptions and remediations
# ---------------------------------------------------------------------------
def generate_description(category: str, evidence: str, asset: str) -> str:
    """
    Return a 3-5 sentence real description explaining what the finding means,
    its security impact, and the protocol/port/service involved.
    Does NOT just copy the raw evidence string.
    """
    c = (category or "").lower()
    ev = (evidence or "").lower()
    a = str(asset or "")

    # --- Port open ---
    if any(tok in c or tok in ev for tok in ("open port", "open_port", "port open", "ports:")):
        nums = re.findall(r"\b(\d{2,5})\b", ev)
        port = nums[0] if nums else "unknown"
        if int(port) in HIGH_PORTS if nums else False:
            return (
                f"TCP port {port} on {a} is accepting connections from the network. "
                f"This port is associated with a high-risk service commonly targeted by "
                f"attackers (e.g., SMB, RDP, databases). If this service is not strictly "
                f"required, it significantly expands the host's attack surface and may "
                f"expose administrative interfaces, unpatched software, or default credentials "
                f"to remote adversaries."
            )
        return (
            f"TCP port {port} on {a} is accepting connections from the network. "
            f"An open port indicates an active listening service that could be probed for "
            f"weak authentication, outdated versions, or known vulnerabilities. If this "
            f"service is not strictly required for business operations, it expands the "
            f"host's attack surface and may expose administrative interfaces, development "
            f"tools, or unpatched software to remote attackers."
        )

    # --- DNS ---
    if any(tok in c or tok in ev for tok in ("dns", "resolved", "reverse dns", "ptr")):
        return (
            f"Forward or reverse DNS resolution succeeded for {a}. DNS lookups reveal the "
            f"host's network identity and can be used by attackers to map the surrounding "
            f"infrastructure. Unrestricted zone transfers or the absence of DNSSEC validation "
            f"can enable spoofing, cache poisoning, or unauthorized enumeration of internal "
            f"hostnames."
        )

    # --- HTTP / banner ---
    if any(tok in c or tok in ev for tok in ("http", "server header", "x-powered-by", "banner")):
        return (
            f"The HTTP service on {a} disclosed version information via response headers "
            f"(Server, X-Powered-By, or similar). Version disclosure allows attackers to "
            f"identify the exact software release in use and cross-reference it against "
            f"public CVE databases to find known exploitable weaknesses. Suppressing version "
            f"information and adding security headers (HSTS, CSP, X-Frame-Options) is a "
            f"fundamental hardening step."
        )

    # --- SSL/TLS ---
    if any(tok in c or tok in ev for tok in ("ssl", "tls", "certificate")):
        return (
            f"An SSL/TLS service was identified on {a}. Weak cipher suites, outdated "
            f"protocol versions (TLS 1.0, 1.1), self-signed certificates, or imminent "
            f"expiration can enable man-in-the-middle attacks or downgrade attacks. "
            f"Modern best practice requires TLS 1.2 or TLS 1.3 with forward-secret "
            f"cipher suites (AES-GCM, ChaCha20) and certificates issued by a trusted CA."
        )

    # --- SQLi ---
    if any(tok in c or tok in ev for tok in ("sqli", "sql injection", "sql_injection")):
        return (
            f"Potential SQL injection vectors were tested against {a}. Successful SQL "
            f"injection allows an attacker to read, modify, or delete database contents, "
            f"bypass authentication, and in some cases escalate to remote code execution "
            f"via xp_cmdshell or INTO OUTFILE. Mitigation requires parameterized queries "
            f"across every data-access path, a WAF as a compensating control, and rigorous "
            f"input validation."
        )

    # --- CVE ---
    if any(tok in c or tok in ev for tok in ("cve", "vulnerability", "exploit")):
        return (
            f"A known CVE or vulnerability was identified on {a}. Public exploit code "
            f"exists for many CVEs, and unpatched systems are frequently compromised "
            f"within days of disclosure. Remediation requires applying vendor patches, "
            f"restricting network access to the affected service, and monitoring for "
            f"exploitation attempts via SIEM rules."
        )

    # --- Default fallback ---
    return (
        f"An informational finding was recorded for {a}. While this observation does not "
        f"directly represent a vulnerability, it contributes to the attacker's "
        f"reconnaissance picture and should be reviewed as part of the overall hardening "
        f"of the target. Verify the business justification for this exposure and apply "
        f"vendor-recommended hardening guidance."
    )


def generate_remediation(category: str, evidence: str, asset: str) -> str:
    """
    Return a specific, applicable remediation. Does NOT use the same generic
    template for all findings.
    """
    c = (category or "").lower()
    ev = (evidence or "").lower()
    a = str(asset or "")

    nums = re.findall(r"\b(\d{2,5})\b", ev)
    port = int(nums[0]) if nums else None

    # --- Port-based remediations ---
    if port in (21,):
        return ("FTP transmits credentials in plaintext. Replace with SFTP or FTPS. "
                "Restrict source IPs via firewall. Disable anonymous login. "
                "Apply latest vendor patches.")
    if port in (22,):
        return ("Restrict SSH source IPs via firewall or VPN. Disable password auth; "
                "enforce key-based authentication. Disable root login. "
                "Enable fail2ban. Apply latest vendor patches (regreSSHion CVE-2024-6387).")
    if port in (23,):
        return ("Telnet transmits all data in plaintext. Replace with SSH. "
                "If unavoidable, tunnel through a VPN and restrict source IPs.")
    if port in (135, 139, 445):
        return ("Disable SMB if not required. Block ports 135/139/445 at the perimeter. "
                "Disable SMBv1. Enforce SMB signing. Apply latest patches (EternalBlue). "
                "Restrict to management jump hosts.")
    if port in (1433, 3306, 5432, 6379, 9200, 27017):
        return ("Bind the database to 127.0.0.1 or a private interface. Require strong "
                "authentication. Disable default accounts (root, sa, admin). Enable TLS "
                "for remote connections. Apply latest security patches. Enable audit logging.")
    if port in (3389,):
        return ("Restrict RDP source IPs via firewall or VPN. Enable Network Level "
                "Authentication (NLA). Enforce MFA. Apply latest patches (BlueKeep "
                "CVE-2019-0708). Consider replacing with a hardened bastion host.")
    if port in (80, 443, 8080, 8443):
        return ("Restrict source IPs to known clients. Redirect HTTP to HTTPS. Enforce "
                "TLS 1.2+. Add security headers (HSTS, CSP, X-Frame-Options, "
                "X-Content-Type-Options). Review web application for OWASP Top 10 issues.")

    # --- DNS ---
    if any(tok in c or tok in ev for tok in ("dns", "resolved", "reverse")):
        return ("Enable DNSSEC. Restrict zone transfers to authorized secondary "
                "nameservers. Monitor for unauthorized DNS changes. Implement DNS "
                "response rate limiting. Enable DNS over TLS/HTTPS where supported.")

    # --- HTTP missing headers ---
    if any(tok in c or tok in ev for tok in ("http", "server header", "banner", "x-powered")):
        return ("Add Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, "
                "X-Content-Type-Options, Referrer-Policy headers. Suppress Server and "
                "X-Powered-By version disclosure. Disable directory listing.")

    # --- SSL/TLS ---
    if any(tok in c or tok in ev for tok in ("ssl", "tls", "certificate")):
        return ("Disable TLS 1.0 and 1.1. Require TLS 1.2+ with strong cipher suites "
                "(AES-GCM, ChaCha20). Renew certificates before expiry. Replace "
                "self-signed certificates with CA-issued equivalents.")

    # --- SQLi ---
    if any(tok in c or tok in ev for tok in ("sqli", "sql injection")):
        return ("Migrate vulnerable parameters to parameterized queries or an ORM. "
                "Deploy a WAF as an interim compensating control. Implement strict "
                "input validation and output encoding. Conduct a code review of all "
                "data-access paths.")

    # --- Generic ---
    return ("Review and remediate per vendor guidance. Apply latest patches, restrict "
            "network access to authorized sources, and monitor for exploitation attempts.")


# ---------------------------------------------------------------------------
# Severity inference (Issue 7: dev ports = LOW)
# ---------------------------------------------------------------------------
def _infer_severity(finding: dict) -> str:
    text = json.dumps(finding).lower()
    if "sqli" in text and ("vulnerable" in text or "injection" in text):
        return "high"
    for token in ("port", "open port", "open_ports", "port "):
        if token in text:
            nums = re.findall(r"\b(\d{2,5})\b", text)
            for n in nums:
                p = int(n)
                if p in HIGH_PORTS:
                    return "high"
                if p in MEDIUM_PORTS:
                    return "medium"
                if p in LOW_PORTS:
                    return "low"
    sev = finding.get("severity", "").lower()
    if sev in SEVERITY_ORDER:
        return sev
    return "info"


def _normalize_findings(raw: Any) -> list[dict]:
    findings = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                cat = item
                findings.append({
                    "title": item,
                    "severity": _infer_severity({"title": item}),
                    "description": generate_description(cat, item, ""),
                    "evidence": item,
                    "remediation": generate_remediation(cat, item, ""),
                })
            elif isinstance(item, dict):
                f = dict(item)
                f.setdefault("severity", _infer_severity(f))
                f.setdefault("title", f.get("title", "Untitled"))
                title = f["title"]
                evidence = f.get("evidence", title)
                f.setdefault("description", generate_description(title, evidence, f.get("affected_asset", "")))
                f.setdefault("remediation", generate_remediation(title, evidence, f.get("affected_asset", "")))
                findings.append(f)
    elif isinstance(raw, dict):
        for key, val in raw.items():
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        findings.append({
                            "title": item,
                            "severity": _infer_severity({"title": item}),
                            "description": generate_description(key, item, ""),
                            "remediation": generate_remediation(key, item, ""),
                        })
                    elif isinstance(item, dict):
                        f = dict(item)
                        f.setdefault("severity", _infer_severity(f))
                        f.setdefault("title", f.get("title", key))
                        title = f["title"]
                        evidence = f.get("evidence", title)
                        f.setdefault("description", generate_description(title, evidence, f.get("affected_asset", "")))
                        f.setdefault("remediation", generate_remediation(title, evidence, f.get("affected_asset", "")))
                        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Issue 4: xhtml2pdf-compatible CSS (no inline-block badges, no border-radius)
# ---------------------------------------------------------------------------
CSS = """
@page {
    size: A4;
    margin: 1.8cm 1.8cm 2.2cm 1.8cm;
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-family: Helvetica, Arial, sans-serif;
        font-size: 8.5pt;
        color: #888;
    }
}
* { box-sizing: border-box; }
body {
    font-family: Helvetica, Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.4;
    color: #222;
    margin: 0;
    padding: 0;
}
h1 { font-size: 20pt; margin: 0 0 6pt 0; page-break-after: avoid; }
h2 {
    font-size: 13pt;
    margin: 0 0 8pt 0;
    padding-bottom: 3pt;
    border-bottom: 1pt solid #2c3e50;
    color: #2c3e50;
    page-break-after: avoid;
}
h3 { font-size: 11pt; margin: 12pt 0 4pt 0; color: #34495e; page-break-after: avoid; }
p { margin: 4pt 0; orphans: 3; widows: 3; }
table {
    width: 100%;
    border-collapse: collapse;
    margin: 8pt 0 12pt 0;
    font-size: 9pt;
    page-break-inside: auto;
}
tr { page-break-inside: avoid; page-break-after: auto; }
th {
    background: #ecf0f1;
    color: #2c3e50;
    font-weight: bold;
    text-align: left;
    padding: 4pt 6pt;
    border: 0.5pt solid #bdc3c7;
}
td {
    padding: 4pt 6pt;
    border: 0.5pt solid #ddd;
    vertical-align: top;
    word-wrap: break-word;
    overflow-wrap: break-word;
}
tr:nth-child(even) { background: #f9f9f9; }
.cover {
    text-align: center;
    padding-top: 100pt;
}
.cover h1 { font-size: 24pt; margin-bottom: 14pt; }
.cover .meta { font-size: 11pt; color: #555; margin-top: 30pt; line-height: 1.6; }
.cover .author { font-size: 13pt; font-weight: bold; margin-top: 24pt; }
.cover .footer-note { font-size: 8pt; color: #888; margin-top: 30pt; }
.toc a { text-decoration: none; color: #222; }
.toc td { border: none; padding: 2pt 6pt; }
.toc { page-break-after: always; }
/* Severity badges — use display:inline (not inline-block) for xhtml2pdf */
.badge {
    padding: 1pt 4pt;
    color: #ffffff;
    font-weight: bold;
    font-size: 8pt;
    text-align: center;
    display: inline;
    line-height: 1.2;
}
.badge-critical { background-color: #8b0000; }
.badge-high { background-color: #c0392b; }
.badge-medium { background-color: #d68910; }
.badge-low { background-color: #2874a6; }
.badge-info { background-color: #5d6d7e; }
.section { page-break-before: always; }
.section:first-of-type { page-break-before: auto; }
.no-break { page-break-inside: avoid; }
pre {
    font-family: 'Courier New', monospace;
    font-size: 8pt;
    background: #fafafa;
    padding: 4pt 6pt;
    border: 0.5pt solid #e0e0e0;
    white-space: pre-wrap;
    word-wrap: break-word;
    margin: 4pt 0 8pt 0;
    line-height: 1.3;
}
.footer-note { font-size: 8pt; color: #888; margin-top: 20pt; text-align: center; }
"""


def _clean_text(text: str) -> str:
    if not text:
        return ""
    s = str(text)
    cleaned = []
    for ch in s:
        cp = ord(ch)
        if cp == 10 or cp == 13:
            cleaned.append(" ")
        elif cp == 9:
            cleaned.append(" ")
        elif 32 <= cp <= 126:
            cleaned.append(ch)
        elif cp >= 160 and cp <= 1114111:
            if 0x2500 <= cp <= 0x25FF:
                continue
            if 0x2600 <= cp <= 0x26FF:
                continue
            cleaned.append(ch)
    result = "".join(cleaned)
    result = re.sub(r" +", " ", result).strip()
    result = result.encode("ascii", "ignore").decode("ascii")
    return result


def _esc(text: str) -> str:
    if not text:
        return ""
    s = _clean_text(text)
    s = s.replace(chr(38), chr(38) + "amp;")
    s = s.replace(chr(60), chr(38) + "lt;")
    s = s.replace(chr(62), chr(38) + "gt;")
    return s


# ---------------------------------------------------------------------------
# Issue 3: Filter mock LLM blocks
# ---------------------------------------------------------------------------
def _filter_real_llm_blocks(llm_blocks: list[str]) -> list[str]:
    """Return only blocks that contain real LLM output (skip mock/fallback)."""
    real = []
    for b in llm_blocks or []:
        if not b:
            continue
        s = str(b).strip()
        if s.startswith("[") and "Would call API with" in s:
            continue
        if "Would call API with" in s:
            continue
        real.append(b)
    return real


def _build_html(target: str, findings: list[dict], meta: dict, cve_text: str, llm_blocks: list[str]) -> str:
    now = datetime.now().strftime("%B %d, %Y")
    operator = meta.get("operator", "HARINISH")
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    total = len(findings)

    # Issue 3: filter mock LLM blocks
    real_llm_blocks = _filter_real_llm_blocks(llm_blocks)
    llm_was_mock = len(real_llm_blocks) == 0 and len(llm_blocks or []) > 0
    llm_was_absent = len(llm_blocks or []) == 0

    # Issue 6: accurate phase counts
    # 8 automated phases + 3 LLM phases
    auto_phases = 8
    if llm_was_absent or llm_was_mock:
        llm_phases_completed = 0
    else:
        llm_phases_completed = min(3, len(real_llm_blocks))
    total_phases_completed = auto_phases + llm_phases_completed

    def findings_table(items, sev_filter=None):
        rows = []
        for f in items:
            sev = f.get("severity", "info").lower()
            if sev_filter and sev != sev_filter:
                continue
            title = f.get('title', '—')
            # Issue 1: use generated description (not raw evidence)
            desc = f.get('description') or generate_description(title, f.get('evidence', ''), f.get('affected_asset', target))
            # Issue 2: use generated remediation (not generic template)
            rem = f.get('remediation') or generate_remediation(title, f.get('evidence', ''), f.get('affected_asset', target))
            badge = f'<span class="badge badge-{sev}">{SEVERITY_LABELS[sev]}</span>'
            rows.append(f"""
            <tr>
                <td>{badge} {_esc(title)}</td>
                <td>{_esc(f.get('affected_asset', target))}</td>
                <td>{_esc(desc)}</td>
                <td>{_esc(rem)}</td>
            </tr>""")
        if not rows:
            return "<p>No findings in this category.</p>"
        return f"""<table>
            <tr><th>Plugin</th><th>Asset</th><th>Description</th><th>Solution</th></tr>
            {''.join(rows)}
        </table>"""

    grouped = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info").lower()
        grouped.setdefault(sev, []).append(f)

    findings_sections = ""
    for sev in SEVERITY_ORDER:
        items = grouped.get(sev, [])
        label = SEVERITY_LABELS[sev]
        findings_sections += f"""
        <div class="section">
        <h2><span class="badge badge-{sev}">{label.upper()}</span> Findings ({len(items)})</h2>
        {findings_table(items, sev_filter=sev)}
        </div>"""

    cve_block = ""
    if cve_text and cve_text != "No service/version pairs matched the local CVE database.":
        cve_block = f"<pre style='font-size:8.5pt;background:#f4f4f4;padding:8pt;'>{_esc(cve_text[:1500])}</pre>"
    else:
        cve_block = "<p>No CVE matches were found in the local knowledge base for the detected services.</p>"

    # Issue 9: LLM analysis section (filtered / renamed / hidden)
    analysis_html = ""
    if real_llm_blocks:
        analysis_html += "<h3>LLM Phase Logs</h3>"
        for i, block in enumerate(real_llm_blocks):
            snippet = _esc(block[:1200])
            analysis_html += f"<div style='margin-bottom:12pt;'><strong>Phase {i+1} Output:</strong><pre style='font-size:8.5pt;background:#fafafa;padding:6pt;white-space:pre-wrap;'>{snippet}</pre></div>"
    elif llm_was_mock:
        analysis_html = "<p>AI analysis was unavailable for this scan (LLM provider returned mock/fallback responses). Findings are based on automated detection rules and CVE matching only.</p>"
    else:
        analysis_html = "<p>No AI analysis output was recorded.</p>"

    recommendations = """
    <ul>
      <li><strong>Patch Management:</strong> Prioritize critical and high-severity findings. Apply vendor patches within 30 days of release. Establish a monthly patch cycle for routine updates and an emergency process for zero-day disclosures.</li>
      <li><strong>Network Segmentation:</strong> Restrict access to sensitive ports (22, 445, 3389, 5432, 6379, 9200) to authorized jump hosts. Implement VLAN isolation between trust zones.</li>
      <li><strong>SSL/TLS Hardening:</strong> Disable TLS 1.0/1.1. Enforce TLS 1.2+ with strong cipher suites. Replace expired or self-signed certificates with CA-issued equivalents.</li>
      <li><strong>Authentication:</strong> Enforce MFA on all remote access services. Rotate default credentials. Disable unused accounts within 30 days of inactivity.</li>
      <li><strong>Monitoring:</strong> Deploy EDR/SIEM coverage for all assets. Baseline normal network behavior and alert on anomalies. Centralize log retention for 90 days minimum.</li>
      <li><strong>SQL Injection:</strong> Migrate vulnerable parameters to parameterized queries or ORM frameworks. Deploy a WAF as an interim compensating control.</li>
      <li><strong>Regular Scans:</strong> Schedule monthly automated scans and quarterly manual penetration tests. Track remediation SLA compliance in a risk register.</li>
      <li><strong>Configuration Management:</strong> Harden OS baselines using CIS Benchmarks. Disable unnecessary services and remove default accounts.</li>
    </ul>
    """

    remediation_rows = []
    for sev in SEVERITY_ORDER:
        for f in grouped.get(sev, []):
            title = f.get('title', '—')
            rem = f.get('remediation') or generate_remediation(title, f.get('evidence', ''), f.get('affected_asset', target))
            badge = f'<span class="badge badge-{sev}">{SEVERITY_LABELS[sev]}</span>'
            remediation_rows.append(f"""
            <tr>
                <td>{badge}</td>
                <td>{_esc(title)}</td>
                <td>{_esc(f.get('affected_asset', target))}</td>
                <td>{_esc(rem)}</td>
            </tr>""")

    remediation_table = f"""<table>
        <tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Remediation Action</th></tr>
        {''.join(remediation_rows)}
    </table>"""

    policy_table = """
    <table>
      <tr><th>Policy Setting</th><th>Recommended Value</th><th>Purpose</th></tr>
      <tr><td>Password History</td><td>24 passwords remembered</td><td>Prevent password reuse</td></tr>
      <tr><td>Maximum Password Age</td><td>120 days</td><td>Force periodic rotation</td></tr>
      <tr><td>Minimum Password Length</td><td>8 characters</td><td>Resist brute-force</td></tr>
      <tr><td>Account Lockout Threshold</td><td>5 invalid attempts</td><td>Thwart credential stuffing</td></tr>
      <tr><td>Lockout Duration</td><td>30 minutes</td><td>Prevent DoS while deterring brute-force</td></tr>
      <tr><td>Reset Lockout Counter</td><td>30 minutes</td><td>Re-enable after cooldown</td></tr>
      <tr><td>Password Complexity</td><td>Enabled (upper, lower, digit, special)</td><td>Enforce strong passwords</td></tr>
      <tr><td>Interactive Logon</td><td>Require Ctrl+Alt+Del</td><td>Prevent credential phishing</td></tr>
      <tr><td>Session Timeout</td><td>15 minutes</td><td>Auto-lock idle sessions</td></tr>
      <tr><td>Audit Logging</td><td>Success + Failure for logon events</td><td>Detect brute-force and lateral movement</td></tr>
    </table>
    """

    open_ports = meta.get("open_ports", [])
    services = meta.get("services", {})
    ports_table_rows = ""
    if open_ports:
        for p in open_ports:
            svc = services.get(str(p), "unknown")
            if p in HIGH_PORTS:
                sev = "high"
            elif p in MEDIUM_PORTS:
                sev = "medium"
            elif p in LOW_PORTS:
                sev = "low"
            else:
                sev = "info"
            badge = f'<span class="badge badge-{sev}">{SEVERITY_LABELS.get(sev, "Info")}</span>'
            ports_table_rows += f"<tr><td>{p}</td><td>{_esc(svc)}</td><td>{badge}</td></tr>"
    else:
        ports_table_rows = "<tr><td colspan='3'>No open ports detected</td></tr>"

    # Issue 6: phase status text
    if llm_was_absent:
        phase_status = "Automated phases: 8/8 — LLM phases: 0/3 (LLM provider not reachable)"
    elif llm_was_mock:
        phase_status = "Automated phases: 8/8 — LLM phases: 0/3 (LLM provider returned mock/fallback responses)"
    else:
        phase_status = f"Automated phases: 8/8 — LLM phases: {llm_phases_completed}/3 — Total: {total_phases_completed}/11"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sample Vulnerability Assessment Report — {target}</title>
<style>
{CSS}
</style>
</head>
<body>

<!-- PAGE 1: COVER PAGE (Issue 8: with explicit break) -->
<div class="cover">
  <h1>Sample Vulnerability Assessment Report</h1>
  <div class="meta">
    <p>Target: <strong>{target}</strong></p>
    <p>Date: {now}</p>
    <p>Operator: {operator}</p>
    <p>LLM Engine: {meta.get('llm_model', 'qwen2.5-coder:7b')}</p>
  </div>
  <div class="author">Prepared by {operator}</div>
  <div class="footer-note">CONFIDENTIAL — Authorized testing only</div>
</div>
<div style="page-break-after: always; height: 1pt;">&nbsp;</div>

<!-- PAGE 2: TABLE OF CONTENTS -->
<div class="section toc">
<h2>Table of Contents</h2>
<table class="toc">
  <tr><td>1.</td><td>Executive Summary</td><td>3</td></tr>
  <tr><td>2.</td><td>Scan Results</td><td>4</td></tr>
  <tr><td>3.</td><td>Methodology</td><td>5</td></tr>
  <tr><td>4.</td><td>Critical Findings</td><td>6</td></tr>
  <tr><td>5.</td><td>High Findings</td><td>7</td></tr>
  <tr><td>6.</td><td>Medium Findings</td><td>8</td></tr>
  <tr><td>7.</td><td>Low Findings</td><td>9</td></tr>
  <tr><td>8.</td><td>Info Findings</td><td>10</td></tr>
  <tr><td>9.</td><td>Risk Assessment</td><td>11</td></tr>
  <tr><td>10.</td><td>Recommendations</td><td>12</td></tr>
  <tr><td>11.</td><td>Remediation</td><td>13–15</td></tr>
  <tr><td>12.</td><td>Security Policy & Configuration</td><td>16</td></tr>
</table>
</div>

<!-- PAGE 3: EXECUTIVE SUMMARY -->
<div class="section">
<h2>1. Executive Summary</h2>
<p>This report documents the findings of an automated security assessment performed against <strong>{target}</strong>.
The assessment was conducted using the NEXUS-STRIKE AI-powered platform, which combines
concurrent network scanning, web application testing, and large-language-model analysis.
The purpose of this assessment was to identify vulnerabilities, misconfigurations, and
security weaknesses that could be exploited by an attacker.</p>

<p><strong>Scope:</strong> The assessment covered TCP port scanning across {len(TOP_PORTS)} common ports,
service identification, banner grabbing, DNS reconnaissance, HTTP fingerprinting,
SQL injection detection, SSL/TLS inspection, AI-driven risk analysis, and CVE enrichment
using a local knowledge base.</p>

<h3>Severity Breakdown</h3>
<table>
  <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
"""
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        pct = f"{cnt/total*100:.1f}%" if total > 0 else "0.0%"
        badge = f'<span class="badge badge-{sev}">{SEVERITY_LABELS[sev]}</span>'
        html += f"  <tr><td>{badge}</td><td>{cnt}</td><td>{pct}</td></tr>\n"

    html += f"""
</table>
<p><strong>Total findings:</strong> {total} &nbsp;|&nbsp; <strong>Scan duration:</strong> {meta.get('elapsed_seconds', '?')}s &nbsp;|&nbsp; <strong>Operator:</strong> {operator}</p>
<p><strong>Open ports detected:</strong> {open_ports if open_ports else 'None'} &nbsp;|&nbsp; <strong>Phase status:</strong> {phase_status}</p>
</div>

<!-- PAGE 4: SCAN RESULTS -->
<div class="section">
<h2>2. Scan Results</h2>
<p>The NEXUS-STRIKE platform executed an 11-phase automated assessment pipeline. This section
presents the supplemental data collected during the scan, including open ports, detected services,
and AI-generated analysis outputs.</p>

<h3>Open Ports & Services</h3>
<table>
  <tr><th>Port</th><th>Service</th><th>Risk</th></tr>
  {ports_table_rows}
</table>

<h3>CVE Enrichment</h3>
{cve_block}

{analysis_html}
</div>

<!-- PAGE 5: METHODOLOGY -->
<div class="section">
<h2>3. Methodology</h2>
<p>The assessment followed an 11-phase methodology designed to maximise coverage
while remaining non-destructive and authorised. Each phase builds on the previous
phase's output to create a comprehensive security picture.</p>
<ol>
  <li><strong>AI Mission Planning</strong> — The LLM is asked to identify the 5 most important security checks for the target, providing a prioritised scope for the assessment.</li>
  <li><strong>TCP Port Scan</strong> — Concurrent socket probe across {len(TOP_PORTS)} common ports using a thread pool. Open ports are recorded with service labels.</li>
  <li><strong>Service Identification</strong> — Port-to-service mapping using well-known IANA signatures and custom heuristics.</li>
  <li><strong>Banner Grabbing</strong> — Raw service banner extraction via socket connect and HTTP HEAD requests for version fingerprinting.</li>
  <li><strong>DNS Reconnaissance</strong> — Forward DNS resolution (gethostbyname) and reverse lookup (gethostbyaddr) to map the target's DNS footprint.</li>
  <li><strong>HTTP Fingerprinting</strong> — HTTP requests to web ports, capturing Server, X-Powered-By headers, and HTTP status codes.</li>
  <li><strong>SQL Injection Detection</strong> — Error-based, boolean-based, and time-based blind SQLi testing using MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR DELAY, Oracle DBMS_PIPE, and SQLite randomblob payloads.</li>
  <li><strong>SSL/TLS Inspection</strong> — SSL socket connection to TLS ports, capturing protocol version, cipher suite, and certificate details.</li>
  <li><strong>AI Risk Analysis</strong> — All findings are fed to the LLM, which identifies high-risk services, attack vectors, and recommended next steps.</li>
  <li><strong>CVE Enrichment</strong> — Service versions are matched against a local CVE knowledge base covering Apache, PHP, MySQL, OpenSSH, Nginx, vsftpd, Samba, Redis, WordPress, and IIS.</li>
  <li><strong>Final Report</strong> — The LLM generates a professional penetration test report with executive summary, scope, findings, and recommendations.</li>
</ol>
</div>

<!-- PAGES 6-10: FINDINGS BY SEVERITY (one page each) -->
{findings_sections}

<!-- PAGE 11: RISK ASSESSMENT -->
<div class="section">
<h2>9. Risk Assessment</h2>
<p>The risk assessment evaluates the overall security posture based on the severity and
density of findings. The following table shows the distribution of findings by severity
level, along with the corresponding risk rating.</p>
<table>
  <tr><th>Severity</th><th>Count</th><th>Percentage</th><th>Risk Level</th></tr>
"""
    risk_levels = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
    for sev in SEVERITY_ORDER:
        cnt = counts.get(sev, 0)
        pct = f"{cnt/total*100:.1f}%" if total > 0 else "0.0%"
        badge = f'<span class="badge badge-{sev}">{SEVERITY_LABELS[sev]}</span>'
        html += f"  <tr><td>{badge}</td><td>{cnt}</td><td>{pct}</td><td>{risk_levels[sev]}</td></tr>\n"

    html += f"""
</table>
<p>Overall risk is determined by the highest severity finding and the density of medium/high findings across the estate.
The current assessment identified <strong>{counts.get('high', 0)} high-severity</strong> and <strong>{counts.get('medium', 0)} medium-severity</strong> findings,
indicating a {'elevated' if counts.get('high', 0) > 0 else 'moderate'} risk posture for <strong>{target}</strong>.</p>
</div>

<!-- PAGE 12: RECOMMENDATIONS -->
<div class="section">
<h2>10. Recommendations</h2>
<p>The following recommendations are prioritised by impact and should be implemented
in the order presented. Each recommendation addresses one or more findings identified
during the assessment.</p>
{recommendations}
</div>

<!-- PAGES 13-15: REMEDIATION -->
<div class="section">
<h2>11. Remediation</h2>
<p>The consolidated remediation table below lists all findings sorted by severity,
along with the specific remediation action required. This table should be used to
track remediation progress and assign ownership.</p>
{remediation_table}
</div>

<!-- PAGE 16: SECURITY POLICY -->
<div class="section">
<h2>12. Security Policy & Configuration</h2>
<p>The following password and lockout policies should be enforced across all Windows
domain controllers and Linux PAM configurations. These settings align with CIS
Benchmarks and NIST SP 800-63B guidelines.</p>
{policy_table}
<h3>Additional Configuration Recommendations</h3>
<ul>
  <li><strong>Firewall Rules:</strong> Default deny inbound. Allow only required ports from trusted sources.</li>
  <li><strong>Encryption at Rest:</strong> Enable BitLocker (Windows) or LUKS (Linux) on all endpoints.</li>
  <li><strong>Backup Strategy:</strong> Follow 3-2-1 rule. Test restores quarterly. Encrypt backup media.</li>
  <li><strong>Access Control:</strong> Implement least privilege. Review access quarterly. Remove orphaned accounts.</li>
  <li><strong>Vulnerability Management:</strong> Scan weekly. Remediate criticals within 7 days, highs within 30 days.</li>
</ul>
</div>

</body>
</html>"""
    return html


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------
XHTML2PDF_CSS = """
@page {
    size: a4 portrait;
    margin: 2cm 2cm 3cm 2cm;
    @frame content_frame {
        left: 50pt;
        width: 512pt;
        top: 50pt;
        height: 700pt;
    }
    @frame footer_frame {
        -pdf-frame-content: footer_content;
        left: 50pt;
        width: 512pt;
        top: 760pt;
        height: 20pt;
    }
}
* { box-sizing: border-box; }
body {
    font-family: Helvetica, Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.4;
    color: #222;
    margin: 0;
    padding: 0;
}
h1 { font-size: 20pt; margin: 0 0 6pt 0; }
h2 {
    font-size: 13pt;
    margin: 18pt 0 8pt 0;
    padding-bottom: 3pt;
    border-bottom: 1pt solid #2c3e50;
    color: #2c3e50;
}
h3 { font-size: 11pt; margin: 12pt 0 4pt 0; color: #34495e; }
table {
    width: 100%;
    border-collapse: collapse;
    margin: 8pt 0 12pt 0;
    font-size: 9pt;
}
th {
    background: #ecf0f1;
    color: #2c3e50;
    font-weight: bold;
    text-align: left;
    padding: 4pt 6pt;
    border: 0.5pt solid #bdc3c7;
}
td {
    padding: 4pt 6pt;
    border: 0.5pt solid #ddd;
    vertical-align: top;
}
.cover {
    text-align: center;
    padding-top: 100pt;
}
.cover h1 { font-size: 24pt; margin-bottom: 14pt; }
.cover .meta { font-size: 11pt; color: #555; margin-top: 30pt; }
.cover .author { font-size: 13pt; font-weight: bold; margin-top: 24pt; }
.toc td { border: none; padding: 2pt 6pt; }
.badge {
    padding: 1pt 4pt;
    color: #ffffff;
    font-weight: bold;
    font-size: 8pt;
    text-align: center;
    display: inline;
}
.badge-critical { background-color: #8b0000; }
.badge-high { background-color: #c0392b; }
.badge-medium { background-color: #d68910; }
.badge-low { background-color: #2874a6; }
.badge-info { background-color: #5d6d7e; }
.section { page-break-before: always; }
.footer-note { font-size: 8pt; color: #888; margin-top: 20pt; text-align: center; }
"""


def _xhtml2pdf_compatible_html(html: str) -> str:
    import re as _re
    html = _re.sub(
        r'<style>.*?</style>',
        f'<style>\n{XHTML2PDF_CSS}\n</style>',
        html,
        count=1,
        flags=_re.DOTALL,
    )
    footer_div = '<div id="footer_content" style="text-align:center; font-size:9pt; color:#666;">Page <pdf:pagenumber> of <pdf:pagecount></div>'
    html = html.replace("</body>", f"{footer_div}\n</body>")
    return html


def render_pdf(html_path: Path, pdf_path: Path) -> Path:
    """Render HTML to PDF. Default to xhtml2pdf (works on Windows without GTK), fallback to others."""
    errors = []

    # Attempt 1: xhtml2pdf (pure Python, works on Windows without GTK) - DEFAULT
    try:
        from xhtml2pdf import pisa  # type: ignore
        html_content = html_path.read_text(encoding="utf-8")
        html_content = _xhtml2pdf_compatible_html(html_content)
        with open(pdf_path, "wb") as f:
            result = pisa.CreatePDF(html_content, dest=f, encoding="utf-8")
        if result.err:
            raise RuntimeError(f"xhtml2pdf reported {result.err} errors")
        return pdf_path
    except Exception as exc1:
        errors.append(f"xhtml2pdf: {exc1}")
        print(f"[!] xhtml2pdf failed ({exc1}), trying weasyprint...")

    # Attempt 2: weasyprint (best CSS support, needs GTK on Windows)
    try:
        import weasyprint  # type: ignore
        weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path
    except Exception as exc2:
        errors.append(f"weasyprint: {exc2}")
        print(f"[!] weasyprint failed ({exc2}), trying playwright...")

    # Attempt 3: playwright (good CSS support, needs browser install)
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1240, "height": 1754})  # A4 @ 96dpi
            page.goto(f"file:///{html_path.as_posix()}")
            page.wait_for_timeout(2000)
            page.pdf(path=str(pdf_path), format="A4", print_background=True, margin={"top": "2cm", "bottom": "2.5cm", "left": "2cm", "right": "2cm"})
            browser.close()
        return pdf_path
    except Exception as exc3:
        errors.append(f"playwright: {exc3}")
        raise RuntimeError("All PDF renderers failed:\n  " + "\n  ".join(errors))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="NEXUS-STRIKE PurpleSec PDF Report Generator")
    ap.add_argument("input", type=Path, help="Path to raw JSON from nexus_scan.py")
    ap.add_argument("--output", "-o", type=Path, default=None, help="Output PDF path")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    data = json.loads(args.input.read_text(encoding="utf-8"))
    findings = _normalize_findings(data.get("findings", data.get("all_findings", [])))
    meta = data.get("_meta", {})
    cve_text = data.get("cve_text", "")
    llm_blocks = data.get("llm_blocks", [])

    if "open_ports" in data:
        meta["open_ports"] = data["open_ports"]
    if "services" in data:
        meta["services"] = data["services"]
    if "sql_findings" in data:
        meta["sql_findings"] = data["sql_findings"]

    target = meta.get("target", args.input.stem)
    operator = meta.get("operator", os.getenv("USERNAME", "HARINISH"))
    meta["operator"] = operator

    html = _build_html(target, findings, meta, cve_text, llm_blocks)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_slug = target.replace("/", "_").replace(":", "_")
    html_path = REPORTS_DIR / f"{target_slug}_{ts}.html"
    pdf_path = args.output or REPORTS_DIR / f"{target_slug}_{ts}.pdf"

    html_path.write_text(html, encoding="utf-8")
    print(f"[*] HTML written: {html_path}")

    render_pdf(html_path, pdf_path)
    print(f"[*] PDF written:  {pdf_path}")

    return pdf_path


if __name__ == "__main__":
    main()
