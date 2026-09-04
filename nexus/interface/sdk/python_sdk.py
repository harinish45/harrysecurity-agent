"""Minimal Python SDK: a thin wrapper around OrchestrationEngine.run_mission()
for embedding a mission in another Python program without going through the
CLI. Not advertised anywhere as more than this — it does not duplicate or
reimplement any mission logic, it just calls the real engine."""
from __future__ import annotations

import asyncio
from typing import Any


class NexusSDK:
    """Programmatic entrypoint to a NEXUS-STRIKE mission."""

    def __init__(self, llm_provider: str | None = None) -> None:
        self._llm_provider = llm_provider

    async def run_mission(
        self,
        target: str,
        *,
        mission_id: str = "sdk-mission",
        mode: str = "guided",
        objective: str = "full_assessment",
        engagement: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from nexus.orchestration.engine import OrchestrationEngine

        engine = OrchestrationEngine(llm_provider=self._llm_provider)
        return await engine.run_mission(
            target=target,
            mission_id=mission_id,
            mode=mode,
            objective=objective,
            engagement=engagement,
        )

    def run_mission_sync(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Synchronous convenience wrapper for callers not already inside
        an event loop (e.g. a plain script)."""
        return asyncio.run(self.run_mission(target, **kwargs))
