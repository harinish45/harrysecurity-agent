"""Constrained local worker for authorized tool execution.

The worker deliberately accepts an argv sequence rather than a shell command.
It bounds runtime and captured output and emits lifecycle events without making
network or authorization decisions on its own.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import subprocess
from time import monotonic
from typing import Sequence
from uuid import uuid4

from nexus.runtime.events import Event, EventBus
from nexus.runtime.tool_metrics import ToolExecutionMetric, ToolMetricsStore
from nexus.runtime.workers import WorkerJob, WorkerResult, WorkerState
from nexus.tools.registry import tool_registry


@dataclass(frozen=True)
class ProcessOutput:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class LocalProcessWorker:
    """Execute a pre-validated argv tuple with bounded process resources."""

    def __init__(
        self,
        event_bus: EventBus | None = None,
        metrics_store: ToolMetricsStore | None = None,
        *,
        max_output_bytes: int = 1_000_000,
    ) -> None:
        if max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be at least 1024")
        self.events = event_bus or EventBus()
        self.metrics = metrics_store or ToolMetricsStore()
        self.max_output_bytes = max_output_bytes

    def execute(self, job: WorkerJob, argv: Sequence[str]) -> WorkerResult:
        job.validate()
        command = self._validate_argv(argv)
        started_monotonic = monotonic()
        started_at = self._timestamp()
        self._publish(job, "worker.started", {"capability": job.capability, "command": command[0]})
        try:
            output = self._run(command, job.timeout_seconds)
        except (OSError, ValueError) as exc:
            self._record_metric(job, started_at, self._timestamp(), started_monotonic, "failed", 0, 0, error_class=type(exc).__name__)
            self._publish(job, "worker.failed", {"error": str(exc)})
            return WorkerResult(job.job_id, WorkerState.FAILED, error=str(exc))

        finished_at = self._timestamp()
        execution_ms = round((monotonic() - started_monotonic) * 1000)
        stdout_bytes = len(output.stdout.encode("utf-8"))
        stderr_bytes = len(output.stderr.encode("utf-8"))

        if output.timed_out:
            self._record_metric(job, started_at, finished_at, started_monotonic, "failed", stdout_bytes, stderr_bytes, execution_ms, "TimeoutExpired")
            self._publish(job, "worker.timeout", {"timeout_seconds": job.timeout_seconds})
            return WorkerResult(job.job_id, WorkerState.FAILED, error="worker timed out")

        if output.returncode != 0:
            error = output.stderr[:4000] or f"process exited with code {output.returncode}"
            self._record_metric(job, started_at, finished_at, started_monotonic, "failed", stdout_bytes, stderr_bytes, execution_ms, "ProcessExit")
            self._publish(job, "worker.failed", {"returncode": output.returncode, "error": error})
            return WorkerResult(job.job_id, WorkerState.FAILED, error=error)

        self._record_metric(job, started_at, finished_at, started_monotonic, "completed", stdout_bytes, stderr_bytes, execution_ms)
        self._publish(job, "worker.completed", {"returncode": output.returncode, "stdout_bytes": stdout_bytes})
        return WorkerResult(job.job_id, WorkerState.COMPLETED)

    def _record_metric(
        self,
        job: WorkerJob,
        started_at: str,
        finished_at: str,
        started_monotonic: float,
        status: str,
        stdout_bytes: int,
        stderr_bytes: int,
        execution_ms: int | None = None,
        error_class: str = "",
    ) -> None:
        resource_class = "unknown"
        try:
            resource_class = tool_registry.get_profile(job.capability).resource_class.value
        except KeyError:
            pass
        self.metrics.add(
            ToolExecutionMetric(
                metric_id=f"metric_{uuid4().hex}",
                mission_id=job.mission_id,
                job_id=job.job_id,
                tool_name=job.capability,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                queue_wait_ms=0,
                execution_ms=execution_ms if execution_ms is not None else round((monotonic() - started_monotonic) * 1000),
                retries=max(0, job.attempt - 1),
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
                resource_class=resource_class,
                error_class=error_class,
            )
        )

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _run(self, argv: tuple[str, ...], timeout: int) -> ProcessOutput:
        try:
            completed = subprocess.run(argv, check=False, shell=False, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            return ProcessOutput(-1, self._bounded_text(exc.stdout), self._bounded_text(exc.stderr), timed_out=True)
        return ProcessOutput(completed.returncode, self._bounded_text(completed.stdout), self._bounded_text(completed.stderr))

    def _bounded_text(self, value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value[: self.max_output_bytes].decode("utf-8", "replace")
        return value.encode("utf-8", "replace")[: self.max_output_bytes].decode("utf-8", "replace")

    @staticmethod
    def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
        command = tuple(str(part) for part in argv)
        if not command or not command[0].strip():
            raise ValueError("worker requires a non-empty argv")
        if any("\x00" in part for part in command):
            raise ValueError("argv cannot contain NUL bytes")
        return command

    def _publish(self, job: WorkerJob, event_type: str, payload: dict[str, object]) -> None:
        self.events.publish(Event(
            event_id=f"job_{job.job_id}_{event_type}_{job.attempt}",
            mission_id=job.mission_id,
            event_type=event_type,
            timestamp=self._timestamp(),
            payload={"job_id": job.job_id, **payload},
        ))
