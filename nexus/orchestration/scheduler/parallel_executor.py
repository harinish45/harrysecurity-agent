"""Runs a batch of independent, synchronous jobs concurrently.

Mission phases used to run in a strict `for phase in plan:` loop even when
nothing depended on the previous phase's output. Agent.run() coroutines do no
real `await`ing internally (their I/O is synchronous tool calls), so simply
`asyncio.gather`-ing them would still serialize on the event loop thread; each
job is instead handed to a bounded thread pool via `run_in_executor`, which is
what actually lets independent phases overlap.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable

from nexus.orchestration.scheduler.resource_allocator import ResourceAllocator


@dataclass
class ExecutionResult:
    key: str
    ok: bool
    value: Any = None
    error: str | None = None


class ParallelExecutor:
    def __init__(self, allocator: ResourceAllocator | None = None) -> None:
        self._allocator = allocator or ResourceAllocator()

    async def run_batch(self, jobs: dict[str, Callable[[], Any]]) -> dict[str, ExecutionResult]:
        if not jobs:
            return {}

        loop = asyncio.get_running_loop()

        async def _run_one(key: str, fn: Callable[[], Any]) -> tuple[str, ExecutionResult]:
            try:
                value = await loop.run_in_executor(self._allocator.pool, fn)
                return key, ExecutionResult(key=key, ok=True, value=value)
            except Exception as exc:  # noqa: BLE001 - captured per-job, not fatal to the batch
                return key, ExecutionResult(key=key, ok=False, error=str(exc))

        pairs = await asyncio.gather(*(_run_one(k, fn) for k, fn in jobs.items()))
        return dict(pairs)
