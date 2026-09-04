"""Direct, retried tool execution — used as a fallback when a mission task
names an agent that doesn't exist, so the task still produces a real (if
narrower) result instead of nothing."""
from __future__ import annotations

from nexus.foundation.schema import STATUS_FAILED, tool_result
from nexus.orchestration.decision.param_optimizer import ParamOptimizer
from nexus.orchestration.recovery.error_handler import ErrorHandler
from nexus.orchestration.recovery.retry_logic import RetryLogic
from nexus.tools.registry import tool_registry


class ActionRunner:
    def __init__(self, retry: RetryLogic | None = None) -> None:
        self._retry = retry or RetryLogic(max_attempts=2)

    async def run_tool(self, tool_name: str, target: str, **kwargs) -> dict:
        async def _call() -> dict:
            timeout = ParamOptimizer.timeout_for(target)
            result = tool_registry.run(tool_name, target=target, timeout=timeout, **kwargs)
            if result.get("status") == STATUS_FAILED and ErrorHandler.should_retry(result.get("error", "")):
                raise RuntimeError(result.get("error", "tool failed"))
            return result

        try:
            return await self._retry.run(_call)
        except Exception as exc:
            return tool_result(tool_name, target, status=STATUS_FAILED, error=str(exc))
