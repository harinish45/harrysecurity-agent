"""Evidence-oriented Markdown reporting for authorised assessments."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import html
from pathlib import Path
import re
from typing import Any, Iterable

from nexus.foundation.schema import Finding, normalize_findings, redact_findings


class ReportGenerator:
    """Generate portable, readable reports without needing an LLM."""

    _severity = ("critical", "high", "medium", "low", "info")

    def generate(
        self,
        findings: Iterable[Any],
        *,
        target: str = "",
        mission_id: str = "assessment",
        engagement: dict[str, Any] | None = None,
        redact: bool = True,
    ) -> str:
        normalised = self.normalize_findings(findings)
        if redact:
            normalised = redact_findings(normalised)
        counts = Counter(item["severity"] for item in normalised)
        engagement = engagement or {}
        created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Sections 4/6/7/8 below are only appended when there's data for
        # them (no asset inventory when findings carry no affected_asset, no
        # verification summary when nothing ran verification_agent, etc.) —
        # a hardcoded "## N." literal per section used to leave a gap in the
        # visible numbering whenever one was skipped (straight from "## 5."
        # to "## 7." with no "## 6."). A running counter keeps every visible
        # heading contiguous regardless of which optional sections appear.
        section_counter = [0]

        def section_heading(title: str) -> str:
            section_counter[0] += 1
            return f"## {section_counter[0]}. {title}"

        # ── Executive summary ───────────────────────────────────────────
        total = len(normalised)
        risk_score = self._compute_risk_score(normalised)
        lines = [
            "# Security Assessment Report",
            "",
            section_heading("Assessment metadata"),
            "",
            f"- **Mission:** `{mission_id}`",
            f"- **Target:** `{target}`",
            f"- **Generated:** {created}",
            f"- **Client:** {engagement.get('client', 'Not provided')}",
            f"- **Authorization reference:** {engagement.get('authorization_reference', 'Not provided')}",
            f"- **Engagement ID:** {engagement.get('id', 'Not provided')}",
            f"- **Rules of engagement:** {engagement.get('rules_of_engagement', 'Not provided')}",
            "",
            section_heading("Executive summary"),
            "",
            f"The assessment recorded **{total}** observations across "
            f"{counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low, and "
            f"{counts['info']} informational findings.",
            "",
            f"**Overall risk score:** {risk_score:.1f}/10.0",
            "",
            "Results are technical observations, not proof of exploitability. "
            "Validate each finding before remediation or escalation.",
            "",
            section_heading("Severity heatmap"),
            "",
        ]

        # ── Severity heatmap ────────────────────────────────────────────
        severity_colors = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        for sev in self._severity:
            bar_len = max(1, counts.get(sev, 0))
            bar = "█" * min(bar_len, 40)
            color = severity_colors.get(sev, "⚪")
            lines.append(f"| {color} **{sev.upper()}** | {bar} ({counts.get(sev, 0)}) |")
        lines.append("")

        # ── Asset inventory ─────────────────────────────────────────────
        assets = set()
        for item in normalised:
            if item.get("affected_asset"):
                assets.add(item["affected_asset"])
        if assets:
            lines.extend([
                section_heading("Asset inventory"),
                "",
            ])
            for asset in sorted(assets):
                asset_findings = [f for f in normalised if f.get("affected_asset") == asset]
                max_sev = max(
                    (self._severity.index(f["severity"]) for f in asset_findings),
                    default=4,
                )
                lines.append(f"- **{asset}** — {len(asset_findings)} findings, "
                             f"worst: {self._severity[max_sev].upper()}")
            lines.append("")

        # ── Scope and rules of engagement ───────────────────────────────
        lines.extend([
            section_heading("Scope and rules of engagement"),
            "",
            f"- **Approved scope:** {engagement.get('scope', target or 'Not provided')}",
            f"- **Rules:** {engagement.get('rules_of_engagement', 'Not provided')}",
            f"- **Exclusions:** {engagement.get('exclusions', 'None specified')}",
            f"- **Emergency stop contact:** {engagement.get('emergency_stop_contact', 'Not provided')}",
            "",
        ])

        # ── Verification summary (verification_agent) ───────────────────
        verified_count = sum(1 for f in normalised if f.get("verification_status") == "verified")
        if any(f.get("verification_status") for f in normalised):
            lines.extend([
                section_heading("Verification summary"),
                "",
                "Every finding below carries a deterministic (non-LLM) replay result where one could be "
                "computed — see `verification_agent`. `non_replayable` means no automated replay evidence "
                "was available, not that the finding is unverified-and-suspect. `likely_false_positive` means "
                "a timing-based claim (e.g. blind/time-based injection) collapsed to baseline network noise "
                "on replay — worth a second look before trusting it.",
                "",
                f"- **Verified:** {verified_count} / {len(normalised)}",
                "",
            ])
            for status in ("verified", "unverified", "likely_false_positive", "failed", "non_replayable"):
                count = sum(1 for f in normalised if f.get("verification_status") == status)
                if count:
                    lines.append(f"  - `{status}`: {count}")
            lines.append("")

        # ── MITRE ATT&CK coverage (mitre_mapping_agent) ──────────────────
        technique_findings: dict[str, list[str]] = {}
        for item in normalised:
            for t in item.get("mitre_techniques") or []:
                key = f"{self._escape(t.get('id', '?'))} — {self._escape(t.get('name', ''))}"
                technique_findings.setdefault(key, []).append(item.get("id", ""))
        if technique_findings:
            lines.extend([section_heading("MITRE ATT&CK coverage"), ""])
            for technique, ids in sorted(technique_findings.items()):
                lines.append(f"- **{technique}** — {len(ids)} finding(s): {', '.join(ids)}")
            lines.append("")

        # ── Attack chains (attack_chain_agent) ───────────────────────────
        chain_findings = [f for f in normalised if f.get("kind") == "synthetic_chain"]
        if chain_findings:
            lines.extend([section_heading("Attack chains"), ""])
            for chain in chain_findings:
                escaped_assets = [self._escape(a) for a in chain.get("chain_assets", [])]
                lines.append(f"- **{chain.get('id')}** ({chain.get('severity', 'info').upper()}): "
                             f"{' -> '.join(escaped_assets)}")
            lines.append("")

        lines.extend([
            section_heading("Findings"),
            "",
        ])

        if not normalised:
            lines.append("No findings were recorded by the selected checks.")
        else:
            for item in normalised:
                fid = item.get("id", "F-???")
                sev = item.get("severity", "info").upper()
                title = item.get("title", "Untitled finding")
                evidence = item.get("evidence", "")
                remediation = item.get("remediation", "")
                references = item.get("references", [])
                confidence = item.get("confidence", "medium")
                tool_name = item.get("tool", "")
                affected = item.get("affected_asset", "")
                verification_status = item.get("verification_status")
                business_impact = item.get("business_impact")
                mitre_techniques = item.get("mitre_techniques") or []

                lines.extend([
                    f"### {fid} — {sev}",
                    "",
                    f"**Title:** {title}",
                    f"**Severity:** {sev} | **Confidence:** {confidence}",
                    f"**Tool:** {tool_name}",
                    f"**Affected asset:** {affected}",
                ])
                if verification_status:
                    lines.append(f"**Verification:** `{verification_status}` — {item.get('verification_detail', '')}")
                if mitre_techniques:
                    tags = ", ".join(
                        f"[{self._escape(t.get('id'))}]({self._escape(t.get('url', ''))}) {self._escape(t.get('name', ''))}"
                        for t in mitre_techniques
                    )
                    lines.append(f"**MITRE ATT&CK:** {tags}")
                if business_impact:
                    lines.append(f"**Business impact:** {self._escape(business_impact)}")
                lines.append("")
                if evidence:
                    lines.extend(["**Evidence:**", "", "```", evidence, "```", ""])
                if remediation:
                    lines.extend(["**Remediation:**", "", remediation, "", ""])
                if references:
                    lines.extend(["**References:**"] + [f"- {ref}" for ref in references] + [""])

        # ── Remediation priorities ──────────────────────────────────────
        lines.extend([
            section_heading("Remediation priorities"),
            "",
            "| Priority | Finding ID | Title | Owner | Due date | Retest status |",
            "|----------|-----------|-------|-------|----------|---------------|",
        ])
        for item in normalised:
            sev_idx = self._severity.index(item.get("severity", "info"))
            priority = "P1" if sev_idx <= 1 else ("P2" if sev_idx == 2 else "P3")
            lines.append(
                f"| {priority} | {item.get('id', '')} | {item.get('title', '')[:50]} | "
                f"TBD | TBD | Pending |"
            )
        lines.append("")

        # ── Evidence appendix ───────────────────────────────────────────
        lines.extend([
            section_heading("Evidence appendix"),
            "",
            "Raw evidence for each finding is included in the finding entries above. "
            "The complete audit log and tool outputs are preserved alongside this report.",
            "",
            "---",
            "",
            "*Report generated by NEXUS-STRIKE. "
            "Preserve this report and the audit log as assessment evidence.*",
            "",
        ])
        return "\n".join(lines)

    def normalize_findings(self, findings: Iterable[Any]) -> list[dict[str, str]]:
        """Convert tool output into the common report/export finding schema."""
        return normalize_findings(list(findings))

    @staticmethod
    def _escape(value: Any) -> str:
        """HTML-escape untrusted finding text before it is embedded in the
        Markdown report. This is a plain-text/Markdown emitter with no HTML
        renderer in this repo, but attacker-controlled fields (asset names in
        attack chains, MITRE technique id/name/url, business_impact) would
        become a live XSS if the .md is ever opened in an HTML-capable
        Markdown viewer, so they are escaped defensively."""
        if value is None:
            return ""
        return html.escape(str(value), quote=True)

    @staticmethod
    def _compute_risk_score(normalised: list[dict]) -> float:
        """Compute a 0-10 risk score based on severity distribution."""
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total = len(normalised) or 1
        score = sum(weights.get(f.get("severity", "info"), 0) for f in normalised)
        # Normalise to 0-10 scale
        return min(10.0, round(score / max(1, total) * 2.5, 1))

    @staticmethod
    def write(report: str, output: str | Path) -> Path:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(report, encoding="utf-8")
        temporary.replace(path)
        return path