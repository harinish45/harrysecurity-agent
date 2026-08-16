"""Bounded, immutable tool execution telemetry."""
from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Iterable


@dataclass(frozen=True)
class ToolExecutionMetric:
    mission_id: str
    job_id: str
    tool_name: str
    status: str
    started_at: float
    finished_at: float
    queue_wait_seconds: float = 0.0
    execution_seconds: float = 0.0
    retries: int = 0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    evidence_count: int = 0
    finding_count: int = 0
    resource_class: str = "unknown"
    error_class: str = ""


class TelemetryStore:
    """Thread-safe bounded in-memory sink; exporters can consume snapshots later."""

    def __init__(self, *, max_items: int = 10_000) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        self.max_items = max_items
        self._items: list[ToolExecutionMetric] = []
        self._lock = Lock()

    def record(self, metric: ToolExecutionMetric) -> None:
        with self._lock:
            self._items.append(metric)
            if len(self._items) > self.max_items:
                del self._items[: len(self._items) - self.max_items]

    def snapshot(self) -> tuple[ToolExecutionMetric, ...]:
        with self._lock:
            return tuple(self._items)

    def extend(self, metrics: Iterable[ToolExecutionMetric]) -> None:
        for metric in metrics:
            self.record(metric)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


telemetry_store = TelemetryStore()
