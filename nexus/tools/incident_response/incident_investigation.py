#!/usr/bin/env python3
"""
NEXUS-STRIKE — incident_response tool: Incident Investigation
Domain: incident_response

Incident investigation means working an actual case file — collected
logs, forensic artifacts, the list of affected assets — to build a
timeline. This previously hashed `target` as if it were a file on disk
(it never was) and checked for hardcoded substrings like "malware"/
"backdoor", always reporting status "completed" — caught during this
session's audit. There is no network-observable substitute for a case
file: a bare target string has no incident to investigate. Now it
honestly reports STATUS_OUT_OF_SCOPE instead of fabricating an
investigation result from an unrelated file hash.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """incident_response tool: Incident Investigation"""
    return tool_result(
        "incident_response.incident_investigation", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Investigating an incident involving {target} requires the case file — "
                f"collected logs, memory/disk artifacts, and the affected-asset list from the "
                f"incident record — a target string alone has no incident timeline to "
                f"investigate",
        error="requires_case_data: no case file/evidence bundle supplied",
        metadata={
            "requires": [
                "incident case file/ticket",
                "collected logs or forensic artifacts",
                "list of affected assets/accounts",
            ],
        },
    )


# Register with tool registry
tool_registry.register("incident_response.incident_investigation", run, metadata={
    "name": "incident_response.incident_investigation",
    "domain": "incident_response",
    "status": "out_of_scope",
    "description": "incident_response tool: investigation requires a real case file (logs, "
                    "artifacts, affected-asset list) — honestly reports STATUS_OUT_OF_SCOPE for "
                    "a bare network target instead of fabricating an investigation result",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
