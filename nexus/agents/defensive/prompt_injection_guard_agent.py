"""Scans mission findings/evidence for prompt-injection attempts embedded in
target-originated content, using ``nexus.foundation.guardrails.InjectionGuard``.

Any hit becomes its own finding (`"Prompt injection attempt detected"`) —
this is treated as a real, reportable security signal about the target, not
noise to be filtered out.

Also does the *other* half of the guard: `check_planner_integrity=True`
periodically round-trips a fresh `InjectionGuard.make_canary()` token
through a live planner-model call and confirms it survives verbatim. That's
a different threat than the findings scan above — it isn't asking "did the
target try to inject us," it's asking "did the planner's own context get
steered by something already in it" (accumulated tool output, a prior
finding, etc.). Opt-in and off by default so a bare `run(findings=[...])`
call in tests never triggers a real LLM call; the engine/caller decides the
cadence ("periodically" per the roadmap) by passing the flag on whichever
mission ticks it chooses.
"""
from __future__ import annotations

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.guardrails.injection_guard import InjectionGuard
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result


class PromptInjectionGuardAgent(BaseAgent):
    name = "prompt_injection_guard_agent"
    description = "defensive agent that scans scanned/target content for prompt-injection attempts"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        findings = kwargs.get("findings", []) or []
        mission_id = kwargs.get("mission_id", "adhoc")

        detections = []
        if kwargs.get("check_planner_integrity"):
            canary_finding = await self._check_planner_canary(mission_id, target)
            if canary_finding:
                detections.append(canary_finding)

        if not findings and not detections:
            return tool_result(self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                                summary="No findings/evidence to scan for prompt injection")
        for f in findings:
            for field_name in ("evidence", "title", "summary"):
                value = f.get(field_name)
                if not isinstance(value, str):
                    continue
                hits = InjectionGuard.scan(value, source=f"{f.get('id', 'F-???')}.{field_name}")
                for hit in hits:
                    detections.append({
                        "id": f"INJ-{len(detections) + 1:03d}",
                        "title": "Prompt injection attempt detected",
                        "severity": "medium",
                        "confidence": "high",
                        "affected_asset": f.get("affected_asset", target),
                        "evidence": f"Matched pattern in {hit['source']}: {hit['match']!r}",
                        "remediation": "Sanitize user/target-controllable content before it reaches any LLM context.",
                        "tool": self.name,
                        "raw": {"source_finding": f.get("id")},
                    })

        if not detections:
            return tool_result(
                self.name, target or "unknown",
                status=STATUS_NO_FINDINGS,
                summary=f"Scanned {len(findings)} finding(s); no prompt-injection patterns detected",
            )

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=detections,
            summary=f"Detected {len(detections)} prompt-injection attempt(s) across {len(findings)} finding(s)",
            metadata={"detection_count": len(detections)},
        )

    async def _check_planner_canary(self, mission_id: str, target: str) -> dict | None:
        """Round-trip a canary through a live LLM call; returns a finding
        dict only if the canary did NOT survive (a real, actionable signal
        that planner context integrity may be compromised), else None so a
        clean check never inflates the findings count."""
        canary = InjectionGuard.make_canary(mission_id)
        try:
            from nexus.intelligence.llm.router import LLMRouter
            output = LLMRouter().complete(
                f"Repeat exactly this token and nothing else: {canary}",
                system="You are a planner-context integrity probe. Output only the exact token given.",
                temperature=0.0,
            )
        except Exception as exc:  # noqa: BLE001 - a failed probe call is inconclusive, not a finding
            return None
        if InjectionGuard.canary_survived(canary, output or ""):
            return None
        return {
            "id": "INJ-PLANNER-001",
            "title": "Planner context integrity check failed",
            "severity": "high",
            "confidence": "medium",
            "affected_asset": target or mission_id,
            "evidence": f"Canary token {canary!r} did not survive a planner round-trip — "
                        "planner context may have been steered by injected content",
            "remediation": "Review recent tool outputs feeding this mission's planner context for "
                            "injection attempts; consider truncating/re-sanitizing before continuing.",
            "tool": self.name,
        }
