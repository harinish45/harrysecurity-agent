#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Detection Engineering Soc
Domain: soc

Building or tuning a detection means deriving rule logic from labeled
example events — true-positive and false-positive samples — against a
specific detection platform's rule syntax. This previously did a DNS
resolve on `target` and GET'd four hardcoded paths (`/alerts`, `/logs`,
`/api/v1/alerts`, `/siem`) against it, reporting whatever HTTP status
came back as "completed" — those paths have nothing to do with building a
detection — caught during this session's audit. A bare target supplies no
example events to derive rule logic from. Now it honestly reports
STATUS_OUT_OF_SCOPE instead of fabricating a detection from an unrelated
HTTP probe.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Detection Engineering Soc"""
    return tool_result(
        "soc.detection_engineering_soc", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Building/tuning a detection covering {target} requires labeled example "
                f"events — true-positive and false-positive samples — to derive rule logic "
                f"from; a bare target supplies no example events",
        error="requires_case_data: no labeled example events supplied",
        metadata={
            "requires": [
                "labeled true-positive example events",
                "labeled false-positive example events",
                "target detection platform's rule syntax",
            ],
        },
    )


# Register with tool registry
tool_registry.register("soc.detection_engineering_soc", run, metadata={
    "name": "soc.detection_engineering_soc",
    "domain": "soc",
    "status": "out_of_scope",
    "description": "soc tool: detection engineering requires labeled true/false-positive "
                    "example events — honestly reports STATUS_OUT_OF_SCOPE for a bare network "
                    "target instead of fabricating a detection rule",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
