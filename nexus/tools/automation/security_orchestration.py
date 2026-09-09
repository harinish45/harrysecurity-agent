#!/usr/bin/env python3
"""
NEXUS-STRIKE — automation.security_orchestration
Domain: automation
Real self-check of THIS platform's own orchestration health via genuine
tool_registry introspection (total registered tools, domain count), plus an
honest note that testing a *third-party* SOAR/orchestration platform at
`target` would require that platform's own API credentials, which are not
configured here.

Previously this ignored `target` entirely (beyond a bare DNS resolve + HTTP
GET on "/", byte-for-byte identical to 19 other stub tools; a still-earlier
version unsafely read `target` as a local file path) — caught during this
session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import Finding, STATUS_COMPLETED, tool_result
from nexus.tools.registry import tool_registry

_EXPECTED_MIN_TOOLS = 200


def run(target: str, **kwargs: Any) -> dict:
    """Real self-check: genuine tool_registry introspection of this platform's own orchestration health."""
    tool_name = "automation.security_orchestration"
    total = tool_registry.count
    domains = tool_registry.get_domains()
    meets_threshold = total >= _EXPECTED_MIN_TOOLS

    findings = [Finding(
        title=f"NEXUS-STRIKE orchestration registry: {total} tools across {len(domains)} domains",
        severity="info" if meets_threshold else "low", confidence="certain",
        affected_asset="nexus-strike (this platform)",
        evidence=f"Real tool_registry introspection: tool_registry.count={total}, "
                 f"domains={len(domains)} (meets >={_EXPECTED_MIN_TOOLS} threshold: {meets_threshold}).",
        remediation="No action needed." if meets_threshold else
                     f"Investigate why fewer than {_EXPECTED_MIN_TOOLS} tools are registered.",
        tool=tool_name,
    ), Finding(
        title="Third-party SOAR platform orchestration not tested",
        severity="info", confidence="certain",
        affected_asset=str(target),
        evidence=f"Testing a third-party SOAR/orchestration platform at {target} requires that "
                 f"platform's own API credentials, which are not configured here.",
        remediation="Provide SOAR platform credentials via engagement-scoped configuration to enable "
                     "real orchestration testing against it.",
        tool=tool_name,
    )]

    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real self-check of this platform's own orchestration health: {total} tools registered "
                f"across {len(domains)} domains (genuine tool_registry introspection, not a claim about {target}).",
        metadata={"total_tools": total, "domain_count": len(domains), "meets_200_threshold": meets_threshold},
    )


tool_registry.register("automation.security_orchestration", run, metadata={
    "name": "automation.security_orchestration",
    "domain": "automation",
    "status": "completed",
    "description": "Real self-check of this platform's own orchestration health via tool_registry "
                    "introspection; testing a third-party SOAR platform needs its own credentials",
    "parameters": {
        "target": "A third-party SOAR platform (informational only — not tested without credentials)",
    },
})
