#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec.dast
Domain: appsec
Real Dynamic Application Security Testing composite: dispatches to the
already-real webapp.xss, webapp.sqli, and webapp.ssrf tools via
tool_registry and aggregates their genuine, network-active findings. Unlike
the other appsec.* tools fixed in this session, DAST is legitimately
network-active — it needs a live, running application, not local source.

Previously this ignored `target` entirely (beyond a bare DNS resolve + HTTP
GET on "/", byte-for-byte identical to 19 other stub tools) and never
actually exercised any dynamic-testing logic — caught during this session's
audit. A target that is obviously a local filesystem path (not a URL/host a
running app could be reached at) degrades honestly to STATUS_OUT_OF_SCOPE
instead of silently no-op'ing.
"""
from __future__ import annotations

import os
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_SUB_TOOLS = ("webapp.xss", "webapp.sqli", "webapp.ssrf")


def run(target: str, **kwargs: Any) -> dict:
    """Real dynamic (DAST) composite: runs webapp.xss/sqli/ssrf against a live target and aggregates results.

    Parameters
    ----------
    target : str
        URL or hostname of a running application to test.
    """
    tool_name = "appsec.dast"
    t = (target or "").strip()
    if not t:
        return tool_result(tool_name, target, status=STATUS_FAILED, error="Empty target")

    if os.path.exists(t) and ("://" not in t):
        return tool_result(
            tool_name, target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"{t} looks like a local filesystem path — appsec.dast performs dynamic testing "
                    f"against a running URL/hostname, not static source. Use appsec.secure_code_review "
                    f"or appsec.dependency_analysis for local source paths instead.",
        )

    findings: list[Finding] = []
    sub_results: dict[str, dict] = {}

    for name in _SUB_TOOLS:
        try:
            fn = tool_registry.get(name)
            r = fn(target=t)
        except Exception as e:  # noqa: BLE001 - sub-tool failures shouldn't abort the composite
            sub_results[name] = {"status": "failed", "error": str(e)[:200]}
            continue

        sub_findings = r.get("findings") or []
        sub_results[name] = {"status": r.get("status"), "finding_count": len(sub_findings)}
        for f in sub_findings:
            if not isinstance(f, dict):
                continue
            merged = dict(f)
            merged["tool"] = tool_name
            merged["evidence"] = f"[via {name}] {merged.get('evidence', '')}"
            findings.append(Finding(**merged))

    completed = sum(1 for v in sub_results.values() if v.get("status") == "completed")
    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"DAST composite ran {len(_SUB_TOOLS)} real dynamic-testing sub-tools "
                f"({', '.join(_SUB_TOOLS)}) against {t} ({completed} completed with activity): "
                f"{len(findings)} aggregated finding(s).",
        metadata={"sub_tool_results": sub_results},
    )


tool_registry.register("appsec.dast", run, metadata={
    "name": "appsec.dast",
    "domain": "appsec",
    "status": "completed",
    "description": "Real DAST composite: dispatches to webapp.xss/sqli/ssrf and aggregates their live findings",
    "parameters": {
        "target": "URL or hostname of a running application to test",
    },
})
