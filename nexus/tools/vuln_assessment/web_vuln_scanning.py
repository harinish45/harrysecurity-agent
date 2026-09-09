#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Web Vuln Scanning
Domain: vuln_assessment

Real composite web vulnerability scan: runs webapp.sqli, webapp.xss, and
cryptography.tls_testing (all real, already-implemented domain tools) via
tool_registry — the same guardrailed entrypoint any agent/dashboard call
goes through — and merges their real findings into one consolidated
vuln-scan report. This tool does no testing of its own; its value is
genuine aggregation of three real scans, not a fourth redundant fake one.

This was previously one of 8 vuln_assessment tools sharing byte-for-byte
identical fake logic (a hardcoded-port TCP scan + bare HTTP GET,
duplicated across all 8 files rather than actually calling the codebase's
real webapp/crypto tools) — caught during this session's audit.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "vuln_assessment.web_vuln_scanning"
_COMPONENT_TOOLS = ("webapp.sqli", "webapp.xss", "cryptography.tls_testing")
_FORWARDABLE_KWARGS = ("timeout", "max_params", "max_payloads", "max_injection_points", "ports")


def run(target: str, **kwargs: Any) -> dict:
    """Real aggregator: runs the real webapp.sqli, webapp.xss, and
    cryptography.tls_testing tools and merges their findings."""
    forwarded = {k: v for k, v in kwargs.items() if k in _FORWARDABLE_KWARGS}

    component_results: dict[str, dict] = {}
    for name in _COMPONENT_TOOLS:
        try:
            component_results[name] = tool_registry.run(name, target=target, **forwarded)
        except Exception as exc:  # noqa: BLE001 - a component tool crashing must not take the aggregator down
            component_results[name] = {"status": STATUS_FAILED, "error": str(exc), "findings": [], "summary": ""}

    all_findings = []
    for r in component_results.values():
        all_findings.extend(r.get("findings", []) or [])

    statuses = [r.get("status") for r in component_results.values()]
    if all_findings:
        status = STATUS_COMPLETED
    elif statuses and all(s == STATUS_FAILED for s in statuses):
        status = STATUS_FAILED
    else:
        status = STATUS_NO_FINDINGS

    severity_counts = Counter(f.get("severity", "info") for f in all_findings)
    severity_summary = ", ".join(f"{sev}:{count}" for sev, count in severity_counts.items())

    summary = (
        f"Consolidated web vulnerability scan for {target}: {len(all_findings)} finding(s) from "
        f"{', '.join(_COMPONENT_TOOLS)}" + (f" ({severity_summary})" if severity_summary else "")
    )

    return tool_result(
        _TOOL_NAME, target, status=status, findings=all_findings, summary=summary,
        metadata={
            "component_tools": {
                name: {"status": r.get("status"), "summary": r.get("summary"), "error": r.get("error")}
                for name, r in component_results.items()
            },
            "severity_counts": dict(severity_counts),
        },
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "Real composite web vulnerability scan — aggregates webapp.sqli + webapp.xss + "
                    "cryptography.tls_testing via tool_registry into one consolidated report",
    "parameters": {
        "target": "Target URL or hostname",
        "timeout": "Optional per-request timeout forwarded to component tools",
        "max_params": "Optional max SQLi params forwarded to webapp.sqli",
        "max_payloads": "Optional max payloads forwarded to component tools",
        "max_injection_points": "Optional max XSS injection points forwarded to webapp.xss",
    },
})
