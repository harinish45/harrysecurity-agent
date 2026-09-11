#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.scanner
Domain: webapp
Lightweight composite "quick scan" aggregator.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no aggregation of anything). Now: a
real orchestrator that calls several other real webapp.* tools through
``tool_registry.run()`` — the guardrailed entrypoint, so every sub-scan
still passes InputGuard/ScopeGuard/LegalGuard/EscalationGuard/RateGuard/
AuditGuard exactly like a directly-invoked scan would — and merges their
findings into one composite result. This is a genuine aggregation of
already-real tool output, not a new detection technique of its own.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

# Kept intentionally small/fast for a "quick scan": four cheap, single-GET-ish
# checks rather than the heavier multi-payload tools (sqli/xss/lfi/...).
DEFAULT_SUBSCANS = [
    "webapp.csrf",
    "webapp.session_mgmt",
    "webapp.waf_detect",
    "webapp.param_discovery",
]


def run(target: str, subscans: list[str] | None = None, timeout: int = 10, **kwargs: Any) -> dict:
    """Run a quick composite scan by aggregating several other webapp.* tools.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    subscans : list[str], optional
        Fully-qualified tool names to run (default: a fixed set of 4 fast
        webapp.* checks). Each is executed via ``tool_registry.run()``, so
        all guardrails apply exactly as they would for a direct call.
    timeout : int
        Per-subscan timeout in seconds, passed through to each sub-tool.
    """
    if not target or not target.strip():
        return tool_result("webapp.scanner", target, status=STATUS_FAILED, error="Empty target")

    tools_to_run = subscans or DEFAULT_SUBSCANS
    findings: list[dict] = []
    sub_results: list[dict] = []
    errors: list[str] = []

    for tool_name in tools_to_run:
        try:
            result = tool_registry.run(tool_name, target=target, timeout=timeout)
        except Exception as e:
            errors.append(f"{tool_name}: {str(e)[:150]}")
            sub_results.append({"tool": tool_name, "status": "failed", "error": str(e)[:150]})
            continue

        sub_status = result.get("status", "failed")
        sub_findings = result.get("findings", [])
        sub_results.append({
            "tool": tool_name,
            "status": sub_status,
            "summary": result.get("summary", ""),
            "finding_count": len(sub_findings),
        })
        if sub_status == "failed":
            errors.append(f"{tool_name}: {result.get('error', 'unknown error')}")
        findings.extend(sub_findings)

    if not sub_results:
        return tool_result("webapp.scanner", target, status=STATUS_FAILED, error="No subscans configured")

    all_failed = all(r["status"] == "failed" for r in sub_results)
    if all_failed:
        return tool_result(
            "webapp.scanner", target,
            status=STATUS_FAILED,
            error="; ".join(errors) or "All subscans failed",
            metadata={"subscans": sub_results},
        )

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = (
        f"Quick scan aggregated {len(tools_to_run)} sub-tool(s): "
        f"{len(findings)} total finding(s) across {sum(1 for r in sub_results if r['status'] == 'completed')} completed "
        f"({sum(1 for r in sub_results if r['status'] == 'no_findings')} clean, "
        f"{sum(1 for r in sub_results if r['status'] == 'failed')} failed)"
    )

    return tool_result(
        "webapp.scanner", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"subscans": sub_results, "errors": errors},
    )


tool_registry.register("webapp.scanner", run, metadata={
    "name": "webapp.scanner",
    "domain": "webapp",
    "status": "completed",
    "description": "Lightweight composite quick-scan: aggregates CSRF, session cookie, WAF-detection, and parameter-discovery findings via tool_registry.run()",
    "parameters": {
        "target": "Target URL or hostname to test",
        "subscans": "Fully-qualified webapp.* tool names to run (default: csrf, session_mgmt, waf_detect, param_discovery)",
        "timeout": "Per-subscan timeout in seconds (default: 10)",
    },
})
