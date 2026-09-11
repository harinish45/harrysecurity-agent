"""Continuous Attack Surface Monitoring.

Runs a fixed set of registered NEXUS tools against a fixed set of targets
through the existing guarded entrypoint, ``ToolExecutor().run()``, records
the results as a baseline, and later re-runs the same tools to diff current
findings against that baseline — surfacing genuinely new findings and
findings that have disappeared ("resolved").

This is deliberately NOT a parallel scanning engine: every scan, baseline
or re-check, goes through ``ToolExecutor.run()``, so it is scope/legal/
rate/audit-guarded exactly like a manual scan — there is no separate
execution path that could bypass those guardrails.

``run_forever`` is a plain blocking ``while`` loop plus ``time.sleep`` — not
asyncio, not its own thread. It is meant to be invoked inside a thread or
separate process the *caller* manages (e.g. ``threading.Thread(target=mon.run_forever, ...)``
or a small supervised script/service); this module does not spawn one
itself. An optional ``max_iterations`` bound exists purely so the loop can
be exercised in tests/bounded runs without actually blocking forever — omit
it for real continuous monitoring.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

from nexus.tools.executor import ToolExecutor

logger = logging.getLogger("nexus.advanced.asm_monitor")


def _finding_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    """Identity used to match a finding across runs.

    (affected_asset, normalized title, tool) — not the finding ``id``,
    since ``id`` is freshly assigned (``F-001`` style) on every run and
    would never match between baseline and re-check.
    """
    return (
        str(finding.get("affected_asset", "")),
        str(finding.get("title", "")).strip().lower(),
        str(finding.get("tool", "")),
    )


class AttackSurfaceMonitor:
    """Baseline-and-diff attack surface monitor built on ``ToolExecutor``."""

    def __init__(self, targets: list[str], executor: Optional[ToolExecutor] = None) -> None:
        self.targets = list(targets)
        self.executor = executor or ToolExecutor()
        self._baseline_results: dict[tuple[str, str], dict[str, Any]] = {}
        self._baseline_findings: dict[tuple[str, str], dict[tuple, dict[str, Any]]] = {}

    def run_baseline(self, tool_names: list[str]) -> dict[tuple[str, str], dict[str, Any]]:
        """Run every ``(target, tool)`` pair once and store it as the baseline."""
        self._baseline_results = {}
        self._baseline_findings = {}
        for target in self.targets:
            for tool_name in tool_names:
                result = self.executor.run(tool_name, target)
                key = (target, tool_name)
                self._baseline_results[key] = result
                self._baseline_findings[key] = {
                    _finding_key(f): f for f in result.get("findings", [])
                }
        return dict(self._baseline_results)

    def check_for_changes(self, tool_names: list[str]) -> list[dict[str, Any]]:
        """Re-run every ``(target, tool)`` pair and diff against the stored baseline.

        After each check, the stored baseline for that ``(target, tool)``
        pair is updated to the just-observed state — this makes
        consecutive calls (as in ``run_forever``) report incremental
        changes rather than re-reporting the same drift on every tick. Call
        ``run_baseline`` again if you want to reset the comparison point.
        """
        if not self._baseline_findings:
            logger.warning(
                "check_for_changes called before run_baseline; every current "
                "finding will be reported as 'new'"
            )

        changes: list[dict[str, Any]] = []
        for target in self.targets:
            for tool_name in tool_names:
                key = (target, tool_name)
                result = self.executor.run(tool_name, target)
                current = {_finding_key(f): f for f in result.get("findings", [])}
                baseline = self._baseline_findings.get(key, {})

                for fkey, finding in current.items():
                    if fkey not in baseline:
                        changes.append({"type": "new", "target": target, "finding": finding})
                for fkey, finding in baseline.items():
                    if fkey not in current:
                        changes.append({"type": "resolved", "target": target, "finding": finding})

                self._baseline_results[key] = result
                self._baseline_findings[key] = current

        return changes

    def run_forever(
        self,
        tool_names: list[str],
        interval_seconds: int,
        on_change: Callable[[list[dict[str, Any]]], None],
        *,
        max_iterations: Optional[int] = None,
    ) -> None:
        """Blocking check/sleep loop. See module docstring for threading notes."""
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            try:
                changes = self.check_for_changes(tool_names)
                if changes:
                    on_change(changes)
            except Exception:
                logger.exception("attack surface monitor iteration failed")
            iterations += 1
            if max_iterations is None or iterations < max_iterations:
                time.sleep(interval_seconds)
