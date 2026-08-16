"""Bounded, immutable execution telemetry for the worker fabric."""
from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Iterable


@dataclass(frozen=True)
class ToolExecutionMetric:
    """A privacy-conscious execution observation; raw argv is never stored."""

    mission_id: str
    job_id: str
    tool_name: str
    status: str
    started_at: float
    finished_at: float
    queue_wait_seconds: float = 0.0
    execution_seconds: float = 0.0
    attempt: int = 1
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    evidence_count: int = 0
    finding_count: int = 0
    resource_class: str = "unknown"
    error_class: str = ""


class TelemetryStore:
    """Thread-safe bounded sink with immutable snapshots."""

    def __init__(self, *, max_items: int = 10_000) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        self.max_items = max_items
        self._items: list[ToolExecutionMetric] = []
        self._lock = Lock()

    def record(self, metric: ToolExecutionMetric) -> None:
        if metric.finished_at < metric.started_at:
            raise ValueError("finished_at cannot precede started_at")
        if metric.attempt < 1:
            raise ValueError("attempt must be positive")
        with self._lock:
            self._items.append(metric)
            overflow = len(self._items) - self.max_items
            if overflow > 0:
                del self._items[:overflow]

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
