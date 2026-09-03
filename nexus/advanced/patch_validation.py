"""Autonomous Patch Validation — regression re-check, NOT auto-patching.

``PatchValidator.verify_fix()`` re-runs the exact ``(tool, target)`` pair
that originally produced a finding, through the same guarded
``ToolExecutor().run()`` every other scan goes through, and checks whether
a matching finding still appears in the fresh results. That is the entirety
of what this module does.

NEXUS-STRIKE has no code anywhere that writes, generates, or applies a
patch — this module does not add one either. "Autonomous" describes the
verification step running without a human re-triggering and re-reading the
scan by hand, not an ability to fix anything. Callers must read a
``verify_fix`` result as "here is what re-running the original check
observed, at this timestamp" — never as "the fix was applied here."

Matching a re-run finding to the original reuses the title-similarity
approach from ``nexus.advanced.triage`` (``difflib.SequenceMatcher`` on the
title, case-insensitive) rather than exact string equality, since tool
output for "the same" issue often varies slightly run to run (counts,
timestamps embedded in a title, etc).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from nexus.advanced.triage import _title_similarity
from nexus.tools.executor import ToolExecutor

_MATCH_THRESHOLD = 0.85


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PatchValidator:
    """Re-tests a claimed fix by re-running the original probe. Does not patch anything."""

    def verify_fix(self, finding: dict[str, Any], executor: Optional[ToolExecutor] = None) -> dict[str, Any]:
        executor = executor or ToolExecutor()
        tool_name = str(finding.get("tool") or "")
        target = str(finding.get("affected_asset") or "")
        original_title = str(finding.get("title", ""))

        if not tool_name or not target:
            return {
                "finding_id": finding.get("id"),
                "still_present": None,
                "verified_at": _now_iso(),
                "rerun_result": {
                    "status": "failed",
                    "summary": "Finding is missing 'tool' and/or 'affected_asset'; cannot re-run the original check.",
                    "finding_count": 0,
                },
            }

        result = executor.run(tool_name, target)
        rerun_findings = result.get("findings", [])
        still_present = any(
            _title_similarity(original_title, str(f.get("title", ""))) >= _MATCH_THRESHOLD
            for f in rerun_findings
        )

        return {
            "finding_id": finding.get("id"),
            "still_present": still_present,
            "verified_at": _now_iso(),
            "rerun_result": {
                "status": result.get("status"),
                "summary": result.get("summary"),
                "finding_count": len(rerun_findings),
            },
        }
