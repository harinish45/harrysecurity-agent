#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Alert Investigation
Domain: soc

Investigating an alert means examining its raw payload — the rule that
fired, the raw event fields, and the surrounding context — from the SIEM/
EDR that generated it. This previously did a DNS resolve on `target` and
GET'd four hardcoded paths (`/alerts`, `/logs`, `/api/v1/alerts`, `/siem`)
against it, reporting whatever HTTP status came back as "completed" —
those paths have nothing to do with `target`'s actual alert data — caught
during this session's audit. A bare domain/IP/URL is not an alert. Now it
honestly reports STATUS_OUT_OF_SCOPE instead of fabricating an
investigation result from an unrelated HTTP probe.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Alert Investigation"""
    return tool_result(
        "soc.alert_investigation", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Investigating an alert concerning {target} requires the raw alert payload "
                f"from the SIEM/EDR — the rule that fired, the raw event fields, and "
                f"surrounding context — a bare domain/IP/URL is not an alert",
        error="requires_case_data: no raw alert payload supplied",
        metadata={
            "requires": [
                "raw alert payload (rule_id, raw event fields, source)",
                "surrounding event context (same host/user, +/- time window)",
                "asset criticality for the alerting host",
            ],
        },
    )


# Register with tool registry
tool_registry.register("soc.alert_investigation", run, metadata={
    "name": "soc.alert_investigation",
    "domain": "soc",
    "status": "out_of_scope",
    "description": "soc tool: alert investigation requires the raw alert payload and "
                    "surrounding event context — honestly reports STATUS_OUT_OF_SCOPE for a "
                    "bare network target instead of fabricating an investigation result",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
