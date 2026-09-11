"""A small heap-based priority queue keyed by the project's severity/priority
labels ("critical" > "high" > "medium" > "low"), used to order tasks that are
otherwise free to run in any order within one dependency batch."""
from __future__ import annotations

import heapq
import itertools
from typing import Any

_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class PriorityQueue:
    def __init__(self) -> None:
        self._heap: list[tuple[int, int, Any]] = []
        self._counter = itertools.count()

    def push(self, item: Any, priority: str = "medium") -> None:
        rank = _RANK.get(str(priority).lower(), 2)
        heapq.heappush(self._heap, (rank, next(self._counter), item))

    def pop(self) -> Any:
        if not self._heap:
            raise IndexError("pop from empty PriorityQueue")
        return heapq.heappop(self._heap)[2]

    def __len__(self) -> int:
        return len(self._heap)

    def drain_sorted(self) -> list[Any]:
        items = []
        while self._heap:
            items.append(self.pop())
        return items
