"""Task dependency resolution — Kahn's algorithm over a task-id graph."""
from __future__ import annotations


class GraphError(Exception):
    """Raised for an unknown dependency reference or a circular dependency."""


class DependencyGraph:
    def __init__(self) -> None:
        self._deps: dict[str, list[str]] = {}

    def add_task(self, task_id: str, depends_on: list[str] | None = None) -> None:
        self._deps[task_id] = list(depends_on or [])

    def batches(self) -> list[list[str]]:
        """Return task ids grouped into ordered batches: every id in batch N
        depends only on ids that finished in batches 0..N-1, so a batch's
        members can run concurrently with each other."""
        for task_id, deps in self._deps.items():
            unknown = [d for d in deps if d not in self._deps]
            if unknown:
                raise GraphError(f"Task '{task_id}' depends on unknown task(s): {unknown}")

        remaining = {k: set(v) for k, v in self._deps.items()}
        done: set[str] = set()
        result: list[list[str]] = []

        while remaining:
            ready = sorted(k for k, deps in remaining.items() if deps <= done)
            if not ready:
                raise GraphError(f"Circular dependency among task(s): {sorted(remaining)}")
            result.append(ready)
            done.update(ready)
            for k in ready:
                del remaining[k]

        return result
