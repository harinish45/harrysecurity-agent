"""Renders one finding data model into mode-appropriate report prose.

`nexus/reporting/templates/*.md` previously shipped as bare one-line H1
stubs (`# Pentest Report`) with nothing reading them. This agent treats a
template's `##` headers as its section skeleton and fills each section
deterministically from the mission's findings/metadata — same underlying
`Finding` data, three (now eight) different renderings depending on mode:
formal audit doc, bounty-platform submission, CTF writeup, etc.
"""
from __future__ import annotations

import re
from pathlib import Path

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, normalize_findings, redact_findings, tool_result

_TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "reporting" / "templates"

_MODE_TEMPLATES = {
    "pentest": "pentest_report.md",
    "redteam": "redteam_report.md",
    "compliance": "compliance_report.md",
    "blueteam": "incident_report.md",
    "bounty": "bounty_report.md",
    "ctf": "ctf_writeup.md",
    "guided": "pentest_report.md",
    "autonomous": "pentest_report.md",
}

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


class ReportToneAgent(BaseAgent):
    name = "report_tone_agent"
    description = "orchestrator agent that renders findings into a mode-appropriate report (audit/bounty/CTF/...)"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        mode = kwargs.get("mode", "pentest")
        findings = redact_findings(normalize_findings(kwargs.get("findings", []) or []))
        template_name = _MODE_TEMPLATES.get(mode, "pentest_report.md")
        template_path = _TEMPLATE_DIR / template_name

        if not template_path.exists():
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED,
                                error=f"Template not found: {template_path}")

        headers = self._parse_headers(template_path.read_text(encoding="utf-8"))
        body = self._render(headers, findings, target, mode, kwargs)

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Rendered {mode} report using {template_name} ({len(findings)} finding(s))",
            metadata={"template": template_name, "rendered_report": body},
        )

    @staticmethod
    def _parse_headers(template_text: str) -> list[str]:
        title = ""
        headers = []
        for line in template_text.splitlines():
            if line.startswith("# ") and not title:
                title = line[2:].strip()
            elif line.startswith("## "):
                headers.append(line[3:].strip())
        return [title] + headers if title else headers

    def _render(self, headers: list[str], findings: list[dict], target: str, mode: str, ctx: dict) -> str:
        lines = []
        title = headers[0] if headers else "Report"
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**Target:** `{target}`  |  **Mode:** `{mode}`  |  **Findings:** {len(findings)}")
        lines.append("")

        for header in headers[1:]:
            lines.append(f"## {header}")
            lines.append("")
            lines.append(self._section_body(header, findings, ctx))
            lines.append("")
        return "\n".join(lines)

    def _section_body(self, header: str, findings: list[dict], ctx: dict) -> str:
        key = re.sub(r"[^a-z ]", "", header.lower()).strip()

        if key in ("summary", "executive summary"):
            counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in _SEVERITY_ORDER}
            if not findings:
                return "No findings were recorded during this engagement."
            return (f"{len(findings)} finding(s) recorded: "
                    f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
                    f"{counts['low']} low, {counts['info']} informational.")

        if key in ("vulnerability type", "category"):
            titles = sorted({f.get("title", "Untitled") for f in findings})[:5]
            return "\n".join(f"- {t}" for t in titles) or "Not applicable."

        if key in ("steps to reproduce", "recon  enumeration", "approach"):
            worst = self._worst_finding(findings)
            if not worst:
                return "No reproducible steps recorded."
            return f"Derived from `{worst.get('tool', 'unknown tool')}` against `{worst.get('affected_asset', '')}`."

        if key in ("proof of concept", "exploit walkthrough"):
            worst = self._worst_finding(findings)
            evidence = worst.get("evidence", "") if worst else ""
            return f"```\n{evidence or 'No evidence captured.'}\n```"

        if key in ("impact", "lessons learned"):
            worst = self._worst_finding(findings)
            impact = (worst or {}).get("business_impact")
            return impact or "Impact not yet annotated by blast_radius_agent for this finding."

        if key in ("suggested severity",):
            worst = self._worst_finding(findings)
            return (worst or {}).get("severity", "info").upper()

        if key in ("remediation",):
            remediations = sorted({f.get("remediation", "") for f in findings if f.get("remediation")})[:5]
            return "\n".join(f"- {r}" for r in remediations) or "No remediation guidance recorded."

        if key in ("timeline",):
            return "Discovered and reported within this assessment window; retest date TBD."

        if key in ("flag",):
            return "See engagement notes — flags are not auto-extracted from findings."

        if key in ("assessment metadata", "target", "scope and rules of engagement"):
            return f"Target: `{ctx.get('target', '')}` — see engagement record for full scope."

        return "See the full findings appendix for supporting detail."

    @staticmethod
    def _worst_finding(findings: list[dict]) -> dict | None:
        if not findings:
            return None
        return min(findings, key=lambda f: _SEVERITY_ORDER.index(f.get("severity", "info"))
                    if f.get("severity") in _SEVERITY_ORDER else len(_SEVERITY_ORDER))
