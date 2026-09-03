"""Markdown compliance gap-analysis report generation.

Mirrors the general style of :mod:`nexus.reporting.generator` (numbered
Markdown sections, a summary near the top, per-item detail below) but is a
distinct, much smaller report: a control-by-control mapping and live
evidence gap-analysis, not a findings report.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from nexus.compliance.evidence_collector import ComplianceEngine
from nexus.compliance.frameworks import FRAMEWORKS, get_mappings

DISCLAIMER = (
    "Illustrative control mapping and gap-analysis tool. This is NOT a certification, "
    "attestation, or audit report, and does not by itself establish compliance with "
    "{framework}. Consult a qualified compliance professional / auditor for actual "
    "certification."
)


def generate_compliance_report(framework: str, engine: "ComplianceEngine | None" = None) -> str:
    if framework not in FRAMEWORKS:
        raise ValueError(f"Unknown framework {framework!r}; expected one of {FRAMEWORKS}")

    engine = engine or ComplianceEngine()
    mappings = get_mappings(framework)
    records = engine.collect_all(framework)
    records_by_id = {record.control_id: record for record in records}
    counts = Counter(record.status for record in records)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    disclaimer = DISCLAIMER.format(framework=framework)

    lines = [
        f"# NEXUS-STRIKE Compliance Gap-Analysis Report — {framework}",
        "",
        f"> **{disclaimer}**",
        "",
        "## 1. Report metadata",
        "",
        f"- **Framework:** `{framework}`",
        f"- **Generated:** {created}",
        f"- **Controls assessed:** {len(mappings)}",
        "",
        "## 2. Summary",
        "",
        "| Status | Count |",
        "|--------|-------|",
        f"| Evidenced | {counts.get('evidenced', 0)} |",
        f"| Partial | {counts.get('partial', 0)} |",
        f"| Gap | {counts.get('gap', 0)} |",
        f"| **Total** | **{len(mappings)}** |",
        "",
        "## 3. Control detail",
        "",
        "| Control ID | Title | NEXUS Capability | Status | Detail |",
        "|---|---|---|---|---|",
    ]

    for mapping in mappings:
        record = records_by_id.get(mapping.control.id)
        capability = mapping.nexus_capability or "—"
        status = record.status if record else "gap"
        detail = (record.detail if record else "No evidence collected.").replace("|", "\\|").replace("\n", " ")
        title = mapping.control.title.replace("|", "\\|")
        lines.append(f"| {mapping.control.id} | {title} | {capability} | {status} | {detail} |")

    lines.append("")
    lines.extend([
        "## 4. Notes",
        "",
        "- **Evidenced** reflects a live, automated check against current NEXUS "
        "configuration/state at report-generation time "
        "(see `nexus/compliance/evidence_collector.py`).",
        "- **Partial** indicates the underlying capability exists in code but this "
        "collector cannot fully verify live enforcement on every call path, or a bounded, "
        "explicit exception is configured.",
        "- **Gap** indicates either no NEXUS capability addresses the control today, or a "
        "live check failed.",
        "",
        "---",
        "",
        f"**{disclaimer}**",
        "",
    ])

    return "\n".join(lines)
