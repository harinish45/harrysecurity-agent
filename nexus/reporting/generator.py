"""Evidence-oriented Markdown reporting for authorised assessments."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Iterable

from nexus.foundation.schema import Finding, normalize_findings


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
    ) -> str:
        normalised = self.normalize_findings(findings)
        counts = Counter(item["severity"] for item in normalised)
        engagement = engagement or {}
        created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # ── Executive summary ───────────────────────────────────────────
        total = len(normalised)
        risk_score = self._compute_risk_score(normalised)
        lines = [
            "# Security Assessment Report",
            "",
            "## 1. Assessment metadata",
            "",
            f"- **Mission:** `{mission_id}`",
            f"- **Target:** `{target}`",
            f"- **Generated:** {created}",
            f"- **Client:** {engagement.get('client', 'Not provided')}",
            f"- **Authorization reference:** {engagement.get('authorization_reference', 'Not provided')}",
            f"- **Engagement ID:** {engagement.get('id', 'Not provided')}",
            f"- **Rules of engagement:** {engagement.get('rules_of_engagement', 'Not provided')}",
            "",
            "## 2. Executive summary",
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
            "## 3. Severity heatmap",
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
                "## 4. Asset inventory",
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
            "## 5. Scope and rules of engagement",
            "",
            f"- **Approved scope:** {engagement.get('scope', target or 'Not provided')}",
            f"- **Rules:** {engagement.get('rules_of_engagement', 'Not provided')}",
            f"- **Exclusions:** {engagement.get('exclusions', 'None specified')}",
            f"- **Emergency stop contact:** {engagement.get('emergency_stop_contact', 'Not provided')}",
            "",
            "## 6. Findings",
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

                lines.extend([
                    f"### {fid} — {sev}",
                    "",
                    f"**Title:** {title}",
                    f"**Severity:** {sev} | **Confidence:** {confidence}",
                    f"**Tool:** {tool_name}",
                    f"**Affected asset:** {affected}",
                    "",
                ])
                if evidence:
                    lines.extend(["**Evidence:**", "", "```", evidence, "```", ""])
                if remediation:
                    lines.extend(["**Remediation:**", "", remediation, "", ""])
                if references:
                    lines.extend(["**References:**"] + [f"- {ref}" for ref in references] + [""])

        # ── Remediation priorities ──────────────────────────────────────
        lines.extend([
            "## 7. Remediation priorities",
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
            "## 8. Evidence appendix",
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