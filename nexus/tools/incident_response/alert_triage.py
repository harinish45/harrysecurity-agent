#!/usr/bin/env python3
"""
NEXUS-STRIKE — incident_response tool: Alert Triage
Domain: incident_response

Alert triage means reading a real alert record — its source, the rule
that fired, the raw event fields, surrounding context — and assigning it
a severity/priority. This previously hashed `target` as if it were a file
on disk (it never was — `target` is a domain/IP/URL) and checked for the
hardcoded substrings "malware"/"backdoor"/"trojan"/"keylog"/"ransom"/
"exploit", always reporting status "completed" even when the "is this a
file" check failed — caught during this session's audit. There is no
network-observable substitute for an alert record: a bare target string
carries no severity, no rule context, and no surrounding events to triage
against. Now it honestly reports STATUS_OUT_OF_SCOPE instead of
fabricating a triage result from an unrelated file hash.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """incident_response tool: Alert Triage"""
    return tool_result(
        "incident_response.alert_triage", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Triaging an alert concerning {target} requires the actual alert record "
                f"(source, rule fired, raw event fields, timestamp) from the SIEM/EDR alert "
                f"queue — a bare domain/IP/URL carries no severity or context signal to "
                f"triage against",
        error="requires_case_data: no alert record supplied — pass the raw alert "
              "JSON/ticket, not a network target",
        metadata={
            "requires": [
                "raw alert event (source, rule_id, timestamp, raw fields)",
                "asset/user context for the alert",
                "historical false-positive rate for the triggering rule",
            ],
        },
    )


# Register with tool registry
tool_registry.register("incident_response.alert_triage", run, metadata={
    "name": "incident_response.alert_triage",
    "domain": "incident_response",
    "status": "out_of_scope",
    "description": "incident_response tool: alert triage requires a real alert record "
                    "(source, rule, raw fields) to assign severity — honestly reports "
                    "STATUS_OUT_OF_SCOPE for a bare network target instead of fabricating a "
                    "triage result",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
