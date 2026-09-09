#!/usr/bin/env python3
"""
NEXUS-STRIKE — purple_team.rule_improvement
Domain: purple_team
Real detection-rule-gap analysis: cross-references an existing detection-
rule inventory against a set of missed/undetected ATT&CK techniques (e.g.
the ``[MISSED]`` findings from purple_team.threat_simulation or any
red_team.*_simulation run) and produces concrete, technique-specific rule
recommendations for the ones with no existing rule. There is no honest way
to recommend rule improvements without knowing what rules already exist and
what actually went undetected, so this tool reports that requirement
explicitly rather than emitting generic advice when neither is supplied.
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
_HIGH_FP_THRESHOLD = 0.10  # 10% false-positive rate flagged as needing tuning


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
    detection_rules: list[dict] | None = None,
    missed_techniques: list[dict] | None = None,
    findings: list[dict] | None = None,
    **kwargs: Any,
) -> dict:
    """Cross-reference a real detection-rule inventory against real missed techniques.

    Parameters
    ----------
    target : str
        Engagement identifier.
    detection_rules : list[dict], optional
        Real existing detection-rule inventory — each entry ideally carries
        ``rule_id``, ``technique_id``, and optionally ``false_positive_rate``
        (0.0-1.0).
    missed_techniques : list[dict], optional
        Real missed/undetected technique records (technique_id + optional
        detection_hint).
    findings : list[dict], optional
        Alternative to `missed_techniques` — the raw findings list from a
        purple_team.threat_simulation or red_team.*_simulation run; entries
        whose title starts with ``[MISSED]`` are treated as missed techniques.
    """
    missed_entries = list(missed_techniques or [])
    if findings:
        for f in findings:
            if isinstance(f, dict) and str(f.get("title", "")).startswith("[MISSED]"):
                missed_entries.append(f)

    if not detection_rules and not missed_entries:
        return tool_result(
            "purple_team.rule_improvement", target,
            status=STATUS_UNAVAILABLE,
            summary=(
                "purple_team.rule_improvement requires real input: pass `detection_rules` "
                "(your real detection-rule/Sigma-rule inventory — a list[dict] with at least "
                "`rule_id` and `technique_id`) AND either `missed_techniques` or `findings` "
                "(the real output of purple_team.threat_simulation or a red_team.*_simulation "
                "run, whose `[MISSED]`-titled entries identify undetected techniques). Without "
                "a real rule inventory to check against, this tool cannot tell you which "
                "missed technique already has a rule versus needs a new one — it will not "
                "guess."
            ),
        )

    if not detection_rules:
        return tool_result(
            "purple_team.rule_improvement", target,
            status=STATUS_UNAVAILABLE,
            summary=(
                f"purple_team.rule_improvement received {len(missed_entries)} missed-technique "
                "record(s) but no `detection_rules` inventory — cannot tell whether a rule "
                "already exists for these techniques (and is just misconfigured) versus needs "
                "to be created from scratch. Pass your real detection-rule export as "
                "`detection_rules` to complete this analysis."
            ),
        )

    if not missed_entries:
        return tool_result(
            "purple_team.rule_improvement", target,
            status=STATUS_UNAVAILABLE,
            summary=(
                f"purple_team.rule_improvement received {len(detection_rules)} detection rule(s) "
                "but no missed-technique data — pass `missed_techniques` or `findings` (the "
                "real output of a threat-simulation run) so this tool knows what actually went "
                "undetected; it will not invent gaps that weren't observed."
            ),
        )

    rules_by_technique: dict[str, list[dict]] = {}
    for rule in detection_rules:
        if not isinstance(rule, dict):
            continue
        tid = _extract_technique_id(rule)
        if tid:
            rules_by_technique.setdefault(tid, []).append(rule)

    findings_out: list[Finding] = []

    # Flag existing rules with a high real false-positive rate as needing tuning.
    for tid, rules in rules_by_technique.items():
        for rule in rules:
            fp_rate = rule.get("false_positive_rate")
            if isinstance(fp_rate, (int, float)) and fp_rate > _HIGH_FP_THRESHOLD:
                findings_out.append(Finding(
                    title=f"Rule tuning needed: {rule.get('rule_id', 'unknown')} for {tid} has {fp_rate:.0%} false-positive rate",
                    severity="medium",
                    confidence="high",
                    affected_asset=target,
                    evidence=f"Existing rule {rule.get('rule_id', 'unknown')} mapped to {tid} reports a "
                             f"{fp_rate:.0%} false-positive rate (threshold: {_HIGH_FP_THRESHOLD:.0%}).",
                    remediation="Tighten this rule's conditions/thresholds to reduce false positives without losing true-positive coverage.",
                    tool="purple_team.rule_improvement",
                    references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
                ))

    new_rules_needed = 0
    for entry in missed_entries:
        if not isinstance(entry, dict):
            continue
        tid = _extract_technique_id(entry)
        if not tid:
            continue
        hint = entry.get("evidence") or entry.get("detection_hint") or ""
        if tid in rules_by_technique:
            existing_ids = ", ".join(r.get("rule_id", "unknown") for r in rules_by_technique[tid])
            findings_out.append(Finding(
                title=f"Existing rule failed to fire: {tid} was missed despite rule(s) {existing_ids}",
                severity="high",
                confidence="high",
                affected_asset=target,
                evidence=f"{tid} was reported missed, but rule(s) {existing_ids} already exist for it "
                         f"— the rule is present but not firing. {hint}",
                remediation=f"Debug rule(s) {existing_ids}: verify the log source is ingested, the "
                            f"query logic matches real event fields, and the rule is enabled.",
                tool="purple_team.rule_improvement",
                references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
            ))
        else:
            new_rules_needed += 1
            findings_out.append(Finding(
                title=f"New detection rule needed: no existing rule covers {tid}",
                severity="high",
                confidence="high",
                affected_asset=target,
                evidence=f"{tid} was missed and no rule in the supplied inventory maps to it. {hint}",
                remediation=f"Create a new detection rule for {tid} based on the expected log source "
                            f"in its detection hint: {hint or 'see MITRE ATT&CK technique page for data sources.'}",
                tool="purple_team.rule_improvement",
                references=[f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"],
            ))

    return tool_result(
        "purple_team.rule_improvement", target,
        status=STATUS_COMPLETED,
        findings=findings_out,
        summary=(
            f"Rule improvement analysis complete: {len(detection_rules)} existing rule(s) checked "
            f"against {len(missed_entries)} missed-technique record(s). {new_rules_needed} technique(s) "
            f"need a brand-new rule; the rest have an existing rule that either needs tuning or debugging."
        ),
        metadata={
            "rules_checked": len(detection_rules),
            "missed_techniques_checked": len(missed_entries),
            "new_rules_needed": new_rules_needed,
            "techniques_with_existing_rules": sorted(rules_by_technique),
        },
    )


tool_registry.register("purple_team.rule_improvement", run, metadata={
    "name": "purple_team.rule_improvement",
    "domain": "purple_team",
    "status": "completed",
    "description": (
        "Real detection-rule-gap analysis — cross-references a real detection-rule inventory "
        "against real missed-technique data to recommend new rules vs. flag existing rules that "
        "are failing to fire or have a high false-positive rate. Honestly reports "
        "STATUS_UNAVAILABLE with a specific explanation when the required real input is missing."
    ),
    "parameters": {
        "target": "Engagement identifier",
        "detection_rules": "Real existing detection-rule inventory (list[dict]: rule_id, technique_id, false_positive_rate)",
        "missed_techniques": "Real missed-technique records (list[dict]: technique_id, detection_hint)",
        "findings": "Alternative: raw findings list from a threat-simulation run ([MISSED]-titled entries used)",
    },
})
