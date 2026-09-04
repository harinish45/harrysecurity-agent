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
from nexus.orchestration.decision.tool_selector import ToolSelector
from nexus.orchestration.flow.action_runner import ActionRunner
from nexus.orchestration.recovery.error_handler import ErrorHandler
from nexus.orchestration.recovery.fallback import Fallback


class SubtaskExecutor:
    def __init__(self, max_attempts: int = 2) -> None:
        self.max_attempts = max(1, max_attempts)

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
        for attempt in range(1, self.max_attempts + 1):
            try:
                agent = agent_cls()
                kwargs: dict[str, Any] = {"target": target}
                if context:
                    kwargs["context"] = context
                result = asyncio.run(agent.run(task, **kwargs))
                result.setdefault("agent", agent_name)
                if result.get("status") == "failed" and ErrorHandler.should_retry(result.get("error", "")):
                    last_error = result.get("error")
                    if attempt < self.max_attempts:
                        continue
                return result
            except Exception as exc:
                last_error = exc
                if attempt < self.max_attempts and ErrorHandler.should_retry(exc):
                    continue
                break

        fallback_agent = Fallback.agent_for(agent_name)
        if fallback_agent:
            try:
                fb = get_agent(fallback_agent)()
                result = asyncio.run(fb.run(task, target=target))
                result.setdefault("agent", fallback_agent)
                result["metadata"] = {**(result.get("metadata") or {}), "fallback_from": agent_name}
                return result
            except Exception as exc:
                last_error = exc

        return Fallback.degraded_result(agent_name, target, task, str(last_error) if last_error else "unknown failure")

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
        return result
