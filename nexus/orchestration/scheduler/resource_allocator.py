"""Bounded worker pool for phase/task-level concurrency.

A dedicated pool, sized from the same `nexus_max_concurrent_tools` config
knob used by nexus.tools.executor's tool-level pool — but kept separate so
phase-level and per-tool concurrency don't contend for the same slots (a
phase blocked waiting on its own tool call shouldn't starve a sibling phase
of its scheduling slot).
"""
from __future__ import annotations

import concurrent.futures

from nexus.foundation.config import config


class ResourceAllocator:
    def __init__(self, max_workers: int | None = None) -> None:
        self.max_workers = (
            max_workers if max_workers is not None
            else max(1, int(getattr(config, "nexus_max_concurrent_tools", 5)))
        )
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="nexus-phase"
        )

    @property
    def pool(self) -> concurrent.futures.ThreadPoolExecutor:
        return self._pool

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)
