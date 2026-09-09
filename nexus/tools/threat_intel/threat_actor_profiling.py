#!/usr/bin/env python3
"""
NEXUS-STRIKE — threat_intel tool: Threat Actor Profiling
Domain: threat_intel

Threat actor profiling fundamentally needs a history of observed TTPs
across multiple incidents — a single target/finding carries no
attribution signal by itself, and this tool never invents an actor name
(that would be pure fabrication no honest data source backs). Given a real
TTP history, it performs a real frequency-aggregation pass and surfaces
the most-recurring techniques as the profile; without one, it honestly
reports that it can't profile anything.

This was previously one of 8 threat_intel tools sharing byte-for-byte
identical fake logic (DNS resolve + bare HTTP GET on `/`, unrelated to
actor profiling) — caught during this session's audit.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "threat_intel.threat_actor_profiling"
_MIN_HISTORY = 3


def run(target: str, **kwargs: Any) -> dict:
    """Real TTP-frequency profiling across a supplied observation history."""
    history = kwargs.get("ttp_history")
    if not isinstance(history, list) or len(history) < _MIN_HISTORY:
        got = len(history) if isinstance(history, list) else 0
        return tool_result(
            _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
            summary="Threat actor profiling needs a TTP history across multiple observed incidents — "
                    "a single target/finding carries no attribution signal",
            error=f"requires_case_data: pass ttp_history=[{{'technique_id': 'T1190', "
                  f"'timestamp': ...}}, ...] with at least {_MIN_HISTORY} entries; got {got}",
        )

    tech_counts: Counter[str] = Counter()
    for entry in history:
        if isinstance(entry, dict):
            tid = entry.get("technique_id") or entry.get("id")
            if tid:
                tech_counts[str(tid)] += 1
        elif isinstance(entry, str) and entry.strip():
            tech_counts[entry.strip()] += 1

    if not tech_counts:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary="ttp_history entries had no recognizable technique_id field to profile",
        )

    top = tech_counts.most_common(10)
    findings = [
        Finding(
            title=f"Recurring TTP: {tid} ({count}x)",
            severity="info",
            confidence="medium",
            affected_asset=target,
            evidence=f"Technique {tid} appears {count} time(s) across the supplied TTP history — a "
                     f"real frequency signal, not an inferred/fabricated actor name or attribution",
            tool=_TOOL_NAME,
            references=[f"https://attack.mitre.org/techniques/{tid}/"],
        )
        for tid, count in top
    ]

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Profiled {len(history)} TTP observation(s) into {len(tech_counts)} distinct "
                f"technique(s); most recurring: {top[0][0]} ({top[0][1]}x)",
        metadata={"technique_frequency": dict(tech_counts)},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "threat_intel",
    "status": "completed",
    "description": "Real TTP-frequency profiling across a supplied multi-incident observation "
                    "history (does not fabricate actor names/attribution)",
    "parameters": {
        "target": "Case/investigation label",
        "ttp_history": "Required: list of 3+ {'technique_id': 'Txxxx', 'timestamp': ...} entries",
    },
})
