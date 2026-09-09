#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Remediation Validation
Domain: vuln_assessment

Real "was this actually fixed" check: re-invokes the exact tool that
originally produced a finding (via tool_registry — the same guardrailed
entrypoint any agent/dashboard call goes through) and checks whether a
matching finding still comes back. When one does, it's handed to
nexus.agents.orchestrator.verification_agent's existing deterministic
replay-and-diff logic (imported and reused, not reimplemented) to get a
real verdict on whether the reproduced finding still holds up.

This was previously one of 8 vuln_assessment tools sharing byte-for-byte
identical fake logic (a hardcoded-port TCP scan + bare HTTP GET, unrelated
to remediation validation) — caught during this session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.agents.orchestrator.verification_agent import VerificationAgent
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "vuln_assessment.remediation_validation"


def run(target: str, **kwargs: Any) -> dict:
    """Re-run the originating tool and diff for whether the finding persists."""
    finding = kwargs.get("finding")
    if not isinstance(finding, dict) or not finding.get("tool"):
        return tool_result(
            _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
            summary="Remediation validation needs the original finding to know what to re-check",
            error="requires_case_data: pass finding={'tool': '<original tool name>', "
                  "'title': '<original title>', ...}",
        )

    original_tool = finding["tool"]
    if original_tool not in tool_registry.list_tools():
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"Unknown originating tool {original_tool!r} — cannot re-invoke it")

    try:
        rerun = tool_registry.run(original_tool, target=target)
    except Exception as exc:  # noqa: BLE001 - surfacing the real failure honestly
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"Re-running {original_tool} for remediation validation failed: {exc}")

    original_title = str(finding.get("title", "")).strip().lower()
    new_findings = rerun.get("findings", []) or []
    still_present = [
        f for f in new_findings
        if original_title and original_title in str(f.get("title", "")).lower()
    ]

    if not still_present:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"Re-ran {original_tool} against {target}: the originally-reported finding "
                    f"{finding.get('title', '')!r} no longer appears (rerun status="
                    f"{rerun.get('status')}) — looks remediated",
            metadata={"rerun_status": rerun.get("status"), "rerun_summary": rerun.get("summary")},
        )

    agent = VerificationAgent()
    v_status, v_detail = agent._verify_one(still_present[0])

    findings = [Finding(
        title=f"Remediation NOT confirmed: {finding.get('title', '')}",
        severity=still_present[0].get("severity", "medium"),
        confidence="high" if v_status == "verified" else "medium",
        affected_asset=target,
        evidence=f"Re-running {original_tool} against {target} still reproduced this finding. "
                 f"Deterministic replay verdict (via verification_agent): {v_status} — {v_detail}",
        remediation="This issue does not appear to be fixed — confirm the intended remediation was "
                    "actually deployed to this target.",
        tool=_TOOL_NAME,
        references=finding.get("references", []) or [],
    )]

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Re-ran {original_tool} against {target}: the original finding still reproduces "
                f"(replay verdict: {v_status})",
        metadata={"rerun_status": rerun.get("status"), "replay_verdict": v_status, "replay_detail": v_detail},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "Real remediation re-check — re-invokes the finding's originating tool via "
                    "tool_registry and reuses verification_agent's replay-and-diff logic",
    "parameters": {
        "target": "Target to re-check",
        "finding": "Required: the original finding dict, needs at least 'tool' and 'title'",
    },
})
