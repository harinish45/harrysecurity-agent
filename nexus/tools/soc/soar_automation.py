#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Soar Automation
Domain: soc

Building a SOAR playbook means defining a trigger condition, a sequence
of actions, and which integrations to call — none of which a bare target
specifies. This previously did a DNS resolve on `target` and GET'd four
hardcoded paths (`/alerts`, `/logs`, `/api/v1/alerts`, `/siem`) against
it, reporting whatever HTTP status came back as "completed" — those paths
have nothing to do with any playbook — caught during this session's
audit. Now it honestly reports STATUS_OUT_OF_SCOPE instead of fabricating
an automation result from an unrelated HTTP probe.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Soar Automation"""
    return tool_result(
        "soc.soar_automation", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Building a SOAR automation/playbook touching {target} requires a playbook "
                f"definition — the trigger condition, the sequence of actions, and which "
                f"integrations to call — a bare target doesn't specify any of that",
        error="requires_case_data: no playbook/trigger definition supplied",
        metadata={
            "requires": [
                "trigger condition (alert type/rule)",
                "action sequence to automate",
                "target integrations (EDR/firewall/ticketing APIs) and their auth",
            ],
        },
    )


# Register with tool registry
tool_registry.register("soc.soar_automation", run, metadata={
    "name": "soc.soar_automation",
    "domain": "soc",
    "status": "out_of_scope",
    "description": "soc tool: SOAR automation requires a playbook's trigger/action/"
                    "integration definition — honestly reports STATUS_OUT_OF_SCOPE for a bare "
                    "network target instead of fabricating an automation result",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
