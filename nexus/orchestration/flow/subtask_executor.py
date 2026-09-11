"""Resolves one mission task to a real nexus.agents.* class and runs it.

This is the piece that actually activates the 60 built agents: the mission
engine used to bypass them entirely and just grab the first few tools
registered under a domain, ignoring the `agent` field on every phase except
for logging. SubtaskExecutor is what the engine now calls instead.
"""
from __future__ import annotations

import asyncio
from typing import Any

from nexus.agents.agent_registry import get_agent
from nexus.foundation.guardrails.injection_guard import InjectionGuard
from nexus.orchestration.decision.tool_selector import ToolSelector
from nexus.orchestration.flow.action_runner import ActionRunner
from nexus.orchestration.recovery.error_handler import ErrorHandler
from nexus.orchestration.recovery.fallback import Fallback


def _scan_result_for_injection(result: dict) -> dict:
    """Deterministic, non-LLM prompt-injection scan applied to every tool/
    agent result the instant it comes back from the target — the earliest
    point target-originated content could steer anything downstream. Hits
    become their own findings rather than being silently stripped; see
    `nexus.foundation.guardrails.InjectionGuard` and
    `prompt_injection_guard_agent` for the mission-level pass over the full
    findings set."""
    findings = result.get("findings")
    if not isinstance(findings, list):
        return result
    extra = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for field_name in ("evidence", "summary", "title"):
            value = f.get(field_name)
            if not isinstance(value, str):
                continue
            for hit in InjectionGuard.scan(value, source=f"{f.get('id', 'F-???')}.{field_name}"):
                extra.append({
                    "title": "Prompt injection attempt detected",
                    "severity": "medium",
                    "confidence": "high",
                    "affected_asset": f.get("affected_asset", result.get("target", "")),
                    "evidence": f"Matched pattern in {hit['source']}: {hit['match']!r}",
                    "remediation": "Sanitize user/target-controllable content before it reaches any LLM context.",
                    "tool": "injection_guard",
                })
    if extra:
        result["findings"] = findings + extra
    return result


class SubtaskExecutor:
    def __init__(self, max_attempts: int = 2, *, reflexion: bool = True) -> None:
        self.max_attempts = max(1, max_attempts)
        self.reflexion = reflexion

    def run_sync(self, task_def: dict[str, Any], context: dict[str, Any] | None = None) -> dict:
        """Synchronous entrypoint, meant to run inside a worker thread (see
        ParallelExecutor) — Agent.run() is a coroutine but performs no real
        async I/O, so running it on the caller's own event loop would
        serialize sibling phases instead of letting them overlap."""
        agent_name = task_def.get("agent", "recon_agent")
        task = task_def.get("task", "")
        target = task_def.get("target", "")

        try:
            agent_cls = get_agent(agent_name)
        except KeyError:
            return self._fallback_to_tool(agent_name, task_def, target, task)

        last_error: BaseException | str | None = None
        current_task = task
        for attempt in range(1, self.max_attempts + 1):
            try:
                agent = agent_cls()
                kwargs: dict[str, Any] = {"target": target}
                if context:
                    kwargs["context"] = context
                result = asyncio.run(agent.run(current_task, **kwargs))
                result.setdefault("agent", agent_name)
                if result.get("status") == "failed" and ErrorHandler.should_retry(result.get("error", "")):
                    last_error = result.get("error")
                    if attempt < self.max_attempts:
                        current_task = self._reflect_and_retry(agent_name, task, last_error)
                        continue
                return _scan_result_for_injection(result)
            except Exception as exc:
                last_error = exc
                if attempt < self.max_attempts and ErrorHandler.should_retry(exc):
                    current_task = self._reflect_and_retry(agent_name, task, last_error)
                    continue
                break

        fallback_agent = Fallback.agent_for(agent_name)
        if fallback_agent:
            try:
                fb = get_agent(fallback_agent)()
                result = asyncio.run(fb.run(task, target=target))
                result.setdefault("agent", fallback_agent)
                result["metadata"] = {**(result.get("metadata") or {}), "fallback_from": agent_name}
                return _scan_result_for_injection(result)
            except Exception as exc:
                last_error = exc

        return Fallback.degraded_result(agent_name, target, task, str(last_error) if last_error else "unknown failure")

    def _reflect_and_retry(self, agent_name: str, original_task: str, error: BaseException | str | None) -> str:
        """Reflexion-style self-critique: instead of blindly repeating the
        same call after a transient failure, ask one cheap LLM call *why*
        the attempt likely failed and fold that into the retry's task
        prompt. Published research on multi-step agent tasks shows this
        measurably beats naive retry loops; if the critique call itself
        fails for any reason, retry proceeds with the original task
        unchanged rather than blocking on it."""
        if not self.reflexion:
            return original_task
        try:
            from nexus.intelligence.llm.router import LLMRouter
            llm = LLMRouter()
            critique = llm.complete(
                f"Agent '{agent_name}' attempted this task and failed:\n"
                f"Task: {original_task}\nError: {error}\n"
                "In one short sentence, say what specifically likely went wrong and what to "
                "change on retry. Do not repeat the task back.",
                system="You are a terse debugging assistant for a security-automation retry loop.",
                temperature=0.2,
            ).strip()
        except Exception:  # noqa: BLE001 - critique is best-effort, never blocks the retry
            return original_task
        if not critique:
            return original_task
        return f"{original_task}\n\n[Reflexion note from prior failed attempt: {critique}]"

    @staticmethod
    def _fallback_to_tool(agent_name: str, task_def: dict[str, Any], target: str, task: str) -> dict:
        """No agent registered under this name — run a representative tool
        for the task's domain directly instead of dropping the task."""
        domain = task_def.get("domain", "")
        candidates = ToolSelector.select(domain, limit=1) if domain else []
        if not candidates or not target:
            return Fallback.degraded_result(agent_name, target, task, f"Unknown agent '{agent_name}'")

        runner = ActionRunner()
        result = asyncio.run(runner.run_tool(candidates[0], target))
        result.setdefault("agent", agent_name)
        result["metadata"] = {**(result.get("metadata") or {}), "resolved_via": "tool_selector"}
        return _scan_result_for_injection(result)
