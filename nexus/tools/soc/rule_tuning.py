#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Rule Tuning
Domain: soc

Tuning a detection rule requires that rule's own alert history — how
often it fires, and how many of those firings were true vs. false
positives — without that history there's nothing to tune. This previously
did a DNS resolve on `target` and GET'd four hardcoded paths (`/alerts`,
`/logs`, `/api/v1/alerts`, `/siem`) against it, reporting whatever HTTP
status came back as "completed" — those paths have nothing to do with any
rule's alert history — caught during this session's audit. Now it
honestly reports STATUS_OUT_OF_SCOPE instead of fabricating a tuning
result from an unrelated HTTP probe.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Rule Tuning"""
    return tool_result(
        "soc.rule_tuning", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Tuning a detection rule related to {target} requires that rule's alert "
                f"history — how often it fires, and how many of those firings were true vs. "
                f"false positives — without that history there's nothing to tune",
        error="requires_case_data: no rule alert-history supplied",
        metadata={
            "requires": [
                "rule definition/ID",
                "alert history with true/false-positive labels",
                "current alert volume and analyst feedback",
            ],
        },
    )


# Register with tool registry
tool_registry.register("soc.rule_tuning", run, metadata={
    "name": "soc.rule_tuning",
    "domain": "soc",
    "status": "out_of_scope",
    "description": "soc tool: rule tuning requires a rule's own alert history with "
                    "true/false-positive labels — honestly reports STATUS_OUT_OF_SCOPE for a "
                    "bare network target instead of fabricating a tuning result",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
