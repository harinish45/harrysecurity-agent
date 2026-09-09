#!/usr/bin/env python3
"""
NEXUS-STRIKE — threat_intel tool: ATT&CK Mapping
Domain: threat_intel

Real reuse of the MITRE ATT&CK technique table nexus/agents/orchestrator/
mitre_mapping_agent.py already maintains for the post-processing pipeline:
imported here, not duplicated, so both paths stay in sync. Maps
finding-shaped input (title/tool/evidence text) to real ATT&CK technique
IDs — falling back to mapping the target string itself when no
finding-shaped input is supplied.

This was previously one of 8 threat_intel tools sharing byte-for-byte
identical fake logic (DNS resolve + bare HTTP GET on `/`, entirely
unrelated to ATT&CK mapping) — caught during this session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.agents.orchestrator.mitre_mapping_agent import _TECHNIQUE_TABLE
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "threat_intel.attck_mapping"


def _techniques_for(haystack: str) -> list[dict[str, str]]:
    haystack = haystack.lower()
    matched: list[dict[str, str]] = []
    seen: set[str] = set()
    for keyword, tid, tname in _TECHNIQUE_TABLE:
        if keyword in haystack and tid not in seen:
            matched.append({"id": tid, "name": tname, "url": f"https://attack.mitre.org/techniques/{tid}/"})
            seen.add(tid)
    return matched


def _input_findings(kwargs: dict[str, Any]) -> list[dict]:
    raw = kwargs.get("findings")
    if raw is None:
        single = kwargs.get("finding")
        raw = [single] if isinstance(single, dict) else None
    if not raw:
        return []
    return [f for f in raw if isinstance(f, dict)]


def run(target: str, **kwargs: Any) -> dict:
    """Map finding-shaped input (or, as a fallback, the target text itself)
    to real MITRE ATT&CK technique IDs using the codebase's existing
    keyword table (imported from mitre_mapping_agent)."""
    input_findings = _input_findings(kwargs)

    if not input_findings:
        techniques = _techniques_for(target)
        if not techniques:
            return tool_result(
                _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
                summary=f"No ATT&CK technique keywords matched target text {target!r}; pass "
                        f"findings=[...] (finding dicts with 'title'/'tool'/'evidence') for real mapping",
            )
        finding = Finding(
            title=f"ATT&CK mapping for target text: {target}",
            severity="info",
            confidence="medium",
            affected_asset=target,
            evidence=f"Matched technique(s) {', '.join(t['id'] for t in techniques)} against target text "
                     f"via the shared keyword table (nexus.agents.orchestrator.mitre_mapping_agent)",
            tool=_TOOL_NAME,
            references=[t["url"] for t in techniques],
        )
        return tool_result(
            _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
            summary=f"Mapped target text to {len(techniques)} ATT&CK technique(s)",
            metadata={"technique_coverage": {t["id"]: t["name"] for t in techniques}},
        )

    annotated = []
    coverage: dict[str, int] = {}
    for f in input_findings:
        haystack = f"{f.get('title', '')} {f.get('tool', '')} {f.get('evidence', '')}"
        techniques = _techniques_for(haystack)
        entry = dict(f)
        entry["mitre_techniques"] = techniques
        for t in techniques:
            coverage[t["id"]] = coverage.get(t["id"], 0) + 1
        annotated.append(entry)

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[],
        summary=f"MITRE ATT&CK mapping applied to {len(annotated)} finding(s); "
                f"{len(coverage)} distinct technique(s) covered",
        metadata={"annotated_findings": annotated, "technique_coverage": coverage},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "threat_intel",
    "status": "completed",
    "description": "Maps finding-shaped input (or target text) to real MITRE ATT&CK technique IDs, "
                    "reusing mitre_mapping_agent's technique table via import",
    "parameters": {
        "target": "Target domain, IP, or a text label (used as fallback mapping input)",
        "findings": "Optional list of finding dicts (title/tool/evidence) to map",
        "finding": "Optional single finding dict, alternative to findings",
    },
})
