"""Drives dependency-aware, concurrency-bounded execution of a mission's
tasks — replaces OrchestrationEngine's previous strictly-sequential
`for phase in plan:` loop, which also never dispatched to a real
nexus.agents.* class in the first place.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.logging import logger
from nexus.orchestration.decision.strategy_engine import StrategyEngine
from nexus.orchestration.flow.subtask_executor import SubtaskExecutor
from nexus.orchestration.flow.task_manager import TaskManager
from nexus.orchestration.handoff.handoff_manager import HandoffManager
from nexus.orchestration.recovery.checkpoint import Checkpoint
from nexus.orchestration.scheduler.parallel_executor import ParallelExecutor
from nexus.orchestration.scheduler.resource_allocator import ResourceAllocator


class FlowController:
    def __init__(self, mission_id: str, *, checkpoint: bool = True) -> None:
        self.mission_id = mission_id
        self._executor = ParallelExecutor(ResourceAllocator())
        self._subtasks = SubtaskExecutor()
        self._checkpoint = Checkpoint() if checkpoint else None
        self.strategy: str | None = None

    async def run(self, tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        batches = TaskManager.plan(tasks)
        self.strategy = StrategyEngine.choose([[t["id"] for t in b] for b in batches])
        logger.info(f"FlowController[{self.mission_id}]: {len(batches)} batch(es), strategy={self.strategy}")

        completed: list[dict[str, Any]] = []
        context: dict[str, Any] = {}

        for batch_num, batch in enumerate(batches, start=1):
            jobs = {
                t["id"]: (lambda task_def=t, ctx=context: self._subtasks.run_sync(task_def, context=ctx))
                for t in batch
            }
            results = await self._executor.run_batch(jobs)

            batch_results = []
            by_id = {t["id"]: t for t in batch}
            for task_id, exec_result in results.items():
                if exec_result.ok:
                    batch_results.append(exec_result.value)
                else:
                    task_def = by_id[task_id]
                    batch_results.append({
                        "agent": task_def.get("agent"),
                        "task": task_def.get("task"),
                        "status": "failed",
                        "error": exec_result.error,
                        "findings": [],
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
