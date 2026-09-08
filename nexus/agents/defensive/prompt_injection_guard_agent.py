"""Scans mission findings/evidence for prompt-injection attempts embedded in
target-originated content, using ``nexus.foundation.guardrails.InjectionGuard``.

Any hit becomes its own finding (`"Prompt injection attempt detected"`) —
this is treated as a real, reportable security signal about the target, not
noise to be filtered out.
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
        if not findings:
            return tool_result(self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                                summary="No findings/evidence to scan for prompt injection")

        detections = []
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
                        "source_finding": f.get("id"),
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
