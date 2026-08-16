"""Structured performance telemetry for tool execution.

Metrics are immutable records. Storage is intentionally abstract so the same
contract can feed local JSONL, PostgreSQL, or an enterprise telemetry backend.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class ToolExecutionMetric:
    metric_id: str
    mission_id: str
    job_id: str
    tool_name: str
    status: str
    started_at: str
    finished_at: str
    queue_wait_ms: int = 0
    execution_ms: int = 0
    retries: int = 0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    evidence_count: int = 0
    finding_count: int = 0
    resource_class: str = "unknown"
    error_class: str = ""

    def validate(self) -> None:
        for name in (
            "queue_wait_ms",
            "execution_ms",
            "retries",
            "stdout_bytes",
            "stderr_bytes",
            "evidence_count",
            "finding_count",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        if not self.metric_id or not self.mission_id or not self.job_id or not self.tool_name:
            raise ValueError("metric identifiers are required")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


class ToolMetricsStore:
    """Thread-safe bounded in-memory metrics store for local deployments."""

    def __init__(self, *, max_records: int = 50_000) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self.max_records = max_records
        self._records: list[ToolExecutionMetric] = []

    def add(self, metric: ToolExecutionMetric) -> ToolExecutionMetric:
        metric.validate()
        self._records.append(metric)
        if len(self._records) > self.max_records:
            del self._records[: len(self._records) - self.max_records]
        return metric

    def list(self, mission_id: str | None = None, tool_name: str | None = None) -> tuple[ToolExecutionMetric, ...]:
        records: Iterable[ToolExecutionMetric] = tuple(self._records)
        if mission_id is not None:
            records = (item for item in records if item.mission_id == mission_id)
        if tool_name is not None:
            records = (item for item in records if item.tool_name == tool_name)
        return tuple(records)

    def summary(self) -> dict[str, object]:
        records = tuple(self._records)
        completed = sum(item.status == "completed" for item in records)
        failed = sum(item.status == "failed" for item in records)
        total_ms = sum(item.execution_ms for item in records)
        avg_ms = round(total_ms / len(records), 2) if records else 0.0
        return {
            "records": len(records),
            "completed": completed,
            "failed": failed,
            "success_rate": round(completed / len(records), 4) if records else 0.0,
            "average_execution_ms": avg_ms,
            "evidence": sum(item.evidence_count for item in records),
            "findings": sum(item.finding_count for item in records),
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
