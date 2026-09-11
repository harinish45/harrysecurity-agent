#!/usr/bin/env python3
"""
NEXUS-STRIKE — incident_response tool: Eradication
Domain: incident_response

Eradication means removing a confirmed compromise — malware, persistence
mechanisms, attacker-created accounts — from an already-identified host.
This previously hashed `target` as if it were a file on disk (it never
was) and checked for hardcoded substrings like "malware"/"backdoor",
always reporting status "completed" — caught during this session's audit.
There is no network-observable substitute for eradication input: a bare
target string doesn't say which host is compromised or what to remove
from it. Now it honestly reports STATUS_OUT_OF_SCOPE instead of
fabricating an eradication result from an unrelated file hash.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """incident_response tool: Eradication"""
    return tool_result(
        "incident_response.eradication", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Eradicating a compromise on/around {target} requires the confirmed IOC set "
                f"(file hashes, registry keys, scheduled tasks, C2 indicators) and the "
                f"identity of the already-compromised host(s) — nothing about a bare target "
                f"tells this tool what to remove",
        error="requires_case_data: no confirmed IOC list or compromised-host identification "
              "supplied",
        metadata={
            "requires": [
                "confirmed IOC list (hashes/paths/C2 domains)",
                "identification of compromised host(s)/account(s)",
                "persistence-mechanism inventory from prior investigation",
            ],
        },
    )


# Register with tool registry
tool_registry.register("incident_response.eradication", run, metadata={
    "name": "incident_response.eradication",
    "domain": "incident_response",
    "status": "out_of_scope",
    "description": "incident_response tool: eradication requires a confirmed IOC set and "
                    "identified compromised host(s) — honestly reports STATUS_OUT_OF_SCOPE for "
                    "a bare network target instead of fabricating an eradication result",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
