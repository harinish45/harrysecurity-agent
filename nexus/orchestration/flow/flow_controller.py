"""Drives dependency-aware, concurrency-bounded execution of a mission's
tasks — replaces OrchestrationEngine's previous strictly-sequential
`for phase in plan:` loop, which also never dispatched to a real
nexus.agents.* class in the first place.
"""
from __future__ import annotations

from typing import Any, Callable

from nexus.foundation.logging import logger
from nexus.orchestration.decision.strategy_engine import StrategyEngine
from nexus.orchestration.flow.subtask_executor import SubtaskExecutor
from nexus.orchestration.flow.task_manager import TaskManager
from nexus.orchestration.handoff.handoff_manager import HandoffManager
from nexus.orchestration.recovery.checkpoint import Checkpoint
from nexus.orchestration.scheduler.parallel_executor import ParallelExecutor
from nexus.orchestration.scheduler.resource_allocator import ResourceAllocator


class FlowController:
    def __init__(self, mission_id: str, *, checkpoint: bool = True,
                on_event: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.mission_id = mission_id
        self._executor = ParallelExecutor(ResourceAllocator())
        self._subtasks = SubtaskExecutor()
        self._checkpoint = Checkpoint() if checkpoint else None
        self.strategy: str | None = None
        # Fires on batch-start and each agent's completion so a caller (the
        # CLI, printing tagged stdout lines the dashboard's WebSocket relay
        # picks up; a future direct dashboard integration) can show live
        # per-agent progress instead of only a post-mission summary.
        # Best-effort: an exception in the callback is logged and swallowed,
        # never allowed to fail the mission.
        self._on_event = on_event

    def _emit(self, event: dict[str, Any]) -> None:
        if not self._on_event:
            return
        try:
            self._on_event({"mission_id": self.mission_id, **event})
        except Exception:  # noqa: BLE001 - progress reporting must never break the mission
            logger.debug("FlowController on_event callback raised", exc_info=True)

    async def run(self, tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        batches = TaskManager.plan(tasks)
        self.strategy = StrategyEngine.choose([[t["id"] for t in b] for b in batches])
        logger.info(f"FlowController[{self.mission_id}]: {len(batches)} batch(es), strategy={self.strategy}")

        completed: list[dict[str, Any]] = []
        context: dict[str, Any] = {}

        for batch_num, batch in enumerate(batches, start=1):
            agent_names = [t.get("agent", "?") for t in batch]
            self._emit({
                "type": "batch_start", "batch": batch_num, "total_batches": len(batches),
                "agents": agent_names,
            })
            jobs = {
                t["id"]: (lambda task_def=t, ctx=context: self._subtasks.run_sync(task_def, context=ctx))
                for t in batch
            }
            results = await self._executor.run_batch(jobs)

            batch_results = []
            by_id = {t["id"]: t for t in batch}
            for task_id, exec_result in results.items():
                task_def = by_id[task_id]
                if exec_result.ok:
                    result = exec_result.value
                    batch_results.append(result)
                    self._emit({
                        "type": "agent_done", "batch": batch_num, "task_id": task_id,
                        "agent": task_def.get("agent"), "status": result.get("status", "completed"),
                        "findings_count": len(result.get("findings") or []),
                    })
                else:
                    batch_results.append({
                        "agent": task_def.get("agent"),
                        "task": task_def.get("task"),
                        "status": "failed",
                        "error": exec_result.error,
                        "findings": [],
                    })
                    self._emit({
                        "type": "agent_done", "batch": batch_num, "task_id": task_id,
                        "agent": task_def.get("agent"), "status": "failed", "error": exec_result.error,
                    })
            completed.extend(batch_results)
            context = HandoffManager.prepare_next_batch(completed)

            if self._checkpoint:
                self._checkpoint.save(self.mission_id, {
                    "batch": batch_num,
                    "total_batches": len(batches),
                    "completed": completed,
                    "context": context,
                })

        if self._checkpoint:
            self._checkpoint.clear(self.mission_id)

        return completed
