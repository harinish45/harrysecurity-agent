#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Ueba
Domain: soc

UEBA (user and entity behavior analytics) is inherently a behavioral-
baseline analysis over historical data — it needs authentication/access
logs for a user or entity across a representative time window, not a
point-in-time network check. This previously did a DNS resolve on
`target` and GET'd four hardcoded paths (`/alerts`, `/logs`,
`/api/v1/alerts`, `/siem`) against it, reporting whatever HTTP status
came back as "completed" — those paths have nothing to do with any
behavioral baseline — caught during this session's audit. A single
point-in-time target has no behavior history to baseline against. Now it
honestly reports STATUS_OUT_OF_SCOPE instead of fabricating a UEBA result
from an unrelated HTTP probe.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Ueba"""
    return tool_result(
        "soc.ueba", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"UEBA analysis for {target} requires a behavioral baseline — authentication/"
                f"access logs for the user or entity over a representative historical "
                f"window — a single point-in-time target has no behavior history to baseline "
                f"against",
        error="requires_case_data: no historical behavior/access logs supplied",
        metadata={
            "requires": [
                "historical auth/access logs for the user or entity",
                "baseline time window (e.g. 30/90 days)",
                "peer-group definition for comparative anomaly scoring",
            ],
        },
    )


# Register with tool registry
tool_registry.register("soc.ueba", run, metadata={
    "name": "soc.ueba",
    "domain": "soc",
    "status": "out_of_scope",
    "description": "soc tool: UEBA requires a historical behavioral baseline (auth/access "
                    "logs over time) for the user/entity — honestly reports "
                    "STATUS_OUT_OF_SCOPE for a bare network target instead of fabricating a "
                    "UEBA result",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
