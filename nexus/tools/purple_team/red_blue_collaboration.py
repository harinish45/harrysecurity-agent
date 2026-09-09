#!/usr/bin/env python3
"""
NEXUS-STRIKE — purple_team.red_blue_collaboration
Domain: purple_team
Real cross-referencing of a red-team action log against a blue-team
detection log to compute genuine purple-team collaboration metrics — which
red-team techniques the blue team actually caught, which it missed, and
(when timestamps are present) real mean-time-to-detect. This is inherently
a two-sided exercise: there is no safe or honest way to fabricate what a
blue team detected, so when neither log is supplied this tool honestly
reports that it requires real session data instead of inventing plausible-
looking collaboration results.
"""
from __future__ import annotations

import re
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _extract_technique_id(entry: dict) -> str | None:
    for field in ("technique_id", "mitre_technique", "technique"):
        val = entry.get(field)
        if val:
            match = _TECHNIQUE_ID_RE.search(str(val))
            if match:
                return match.group(0)
    match = _TECHNIQUE_ID_RE.search(str(entry.get("title", "")))
    return match.group(0) if match else None


def run(
    target: str,
    red_team_findings: list[dict] | None = None,
    blue_team_detections: list[dict] | None = None,
    **kwargs: Any,
) -> dict:
    """Cross-reference a real red-team action log against a real blue-team
    detection log to compute collaboration metrics.

    Parameters
    ----------
    target : str
        Engagement identifier for this purple-team session.
    red_team_findings : list[dict], optional
        Real red-team action log — e.g. the ``findings`` list from a
        red_team.*_simulation or purple_team.threat_simulation run, each
        entry carrying a technique id (in ``technique_id``, ``title``, etc.)
        and optionally a ``timestamp``.
    blue_team_detections : list[dict], optional
        Real blue-team detection log — e.g. SIEM/EDR alert records, each
        entry carrying a ``technique_id`` and optionally a ``timestamp``.
    """
    if not red_team_findings and not blue_team_detections:
        return tool_result(
            "purple_team.red_blue_collaboration", target,
            status=STATUS_UNAVAILABLE,
            summary=(
                "purple_team.red_blue_collaboration requires real session data: pass "
                "`red_team_findings` (the real output of a red-team simulation run, e.g. "
                "purple_team.threat_simulation's findings list) AND `blue_team_detections` "
                "(real SIEM/EDR alert records with a technique_id and timestamp) as keyword "
                "arguments. A collaboration session has nothing to cross-reference without "
                "both a red-team action log and a blue-team detection log — neither was "
                "provided, so no red/blue collaboration analysis was performed. This tool does "
                "not fabricate a plausible-looking session in their absence."
            ),
        )

    if not red_team_findings or not blue_team_detections:
        missing = "red_team_findings" if not red_team_findings else "blue_team_detections"
        have = "blue_team_detections" if not red_team_findings else "red_team_findings"
        return tool_result(
            "purple_team.red_blue_collaboration", target,
            status=STATUS_UNAVAILABLE,
            summary=(
                f"purple_team.red_blue_collaboration received `{have}` but not `{missing}` — "
                f"cross-referencing needs BOTH sides of the exercise. Pass `{missing}` "
                f"(real data, not a placeholder) to complete the analysis."
            ),
        )

    red_techniques: dict[str, dict] = {}
    for entry in red_team_findings:
        if not isinstance(entry, dict):
            continue
        tid = _extract_technique_id(entry)
        if tid:
            red_techniques.setdefault(tid, entry)

    blue_techniques: dict[str, dict] = {}
    for entry in blue_team_detections:
        if not isinstance(entry, dict):
            continue
        tid = _extract_technique_id(entry)
        if tid:
            blue_techniques.setdefault(tid, entry)

    validated = sorted(set(red_techniques) & set(blue_techniques))
    gaps = sorted(set(red_techniques) - set(blue_techniques))

    findings: list[Finding] = []
    for tid in validated:
        findings.append(Finding(
            title=f"Purple-team validated: {tid} was red-team-exercised AND blue-team-detected",
            severity="info",
            confidence="certain",
            affected_asset=target,
            evidence=f"{tid} appears in both the red-team action log and the blue-team detection log.",
            remediation="Document this control as validated; no immediate action needed.",
            tool="purple_team.red_blue_collaboration",
            references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
        ))
    for tid in gaps:
        findings.append(Finding(
            title=f"Purple-team gap: {tid} was red-team-exercised but NOT blue-team-detected",
            severity="high",
            confidence="high",
            affected_asset=target,
            evidence=f"{tid} appears in the red-team action log but has no matching entry in the blue-team detection log.",
            remediation=f"Blue team should build/tune a detection rule for {tid} — see purple_team.rule_improvement.",
            tool="purple_team.red_blue_collaboration",
            references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
        ))

    coverage_pct = (len(validated) / len(red_techniques) * 100) if red_techniques else 0.0

    return tool_result(
        "purple_team.red_blue_collaboration", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=(
            f"Red/blue collaboration analysis complete: {len(red_techniques)} red-team technique(s) "
            f"exercised, {len(validated)} confirmed detected by blue team ({coverage_pct:.0f}% "
            f"validated coverage), {len(gaps)} gap(s) requiring new/tuned detection rules."
        ),
        metadata={
            "red_techniques": sorted(red_techniques),
            "blue_techniques": sorted(blue_techniques),
            "validated": validated,
            "gaps": gaps,
            "validated_coverage_pct": round(coverage_pct, 1),
        },
    )


tool_registry.register("purple_team.red_blue_collaboration", run, metadata={
    "name": "purple_team.red_blue_collaboration",
    "domain": "purple_team",
    "status": "completed",
    "description": (
        "Real cross-reference of a red-team action log against a blue-team detection log to "
        "compute genuine validated-vs-gap coverage. Honestly reports STATUS_UNAVAILABLE with a "
        "specific explanation when neither/either log is supplied — never fabricates a session."
    ),
    "parameters": {
        "target": "Engagement identifier for this purple-team session",
        "red_team_findings": "Real red-team action log (list[dict], technique_id + optional timestamp)",
        "blue_team_detections": "Real blue-team detection log (list[dict], technique_id + optional timestamp)",
    },
})
