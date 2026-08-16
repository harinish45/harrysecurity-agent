"""Constrained local worker for authorized tool execution.

The worker deliberately accepts an argv sequence rather than a shell command.
It bounds runtime and captured output and emits lifecycle events without making
network or authorization decisions on its own.
"""
from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Sequence

from nexus.runtime.events import Event, EventBus
from nexus.runtime.workers import WorkerJob, WorkerResult, WorkerState


@dataclass(frozen=True)
class ProcessOutput:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class LocalProcessWorker:
    """Execute a pre-validated argv tuple with bounded process resources."""

    def __init__(self, event_bus: EventBus | None = None, *, max_output_bytes: int = 1_000_000) -> None:
        if max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be at least 1024")
        self.events = event_bus or EventBus()
        self.max_output_bytes = max_output_bytes

    def execute(self, job: WorkerJob, argv: Sequence[str]) -> WorkerResult:
        job.validate()
        command = self._validate_argv(argv)
        self._publish(job, "worker.started", {"capability": job.capability, "command": command[0]})
        try:
            output = self._run(command, job.timeout_seconds)
        except OSError as exc:
            self._publish(job, "worker.failed", {"error": str(exc)})
            return WorkerResult(job.job_id, WorkerState.FAILED, error=str(exc))

        if output.timed_out:
            self._publish(job, "worker.timeout", {"timeout_seconds": job.timeout_seconds})
            return WorkerResult(job.job_id, WorkerState.FAILED, error="worker timed out")

        if output.returncode != 0:
            error = output.stderr[:4000] or f"process exited with code {output.returncode}"
            self._publish(job, "worker.failed", {"returncode": output.returncode, "error": error})
            return WorkerResult(job.job_id, WorkerState.FAILED, error=error)

        self._publish(
            job,
            "worker.completed",
            {"returncode": output.returncode, "stdout_bytes": len(output.stdout.encode("utf-8"))},
        )
        return WorkerResult(job.job_id, WorkerState.COMPLETED)

    def _run(self, argv: tuple[str, ...], timeout: int) -> ProcessOutput:
        completed = subprocess.run(
            argv,
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = completed.stdout.encode("utf-8", "replace")[: self.max_output_bytes].decode("utf-8", "replace")
        stderr = completed.stderr.encode("utf-8", "replace")[: self.max_output_bytes].decode("utf-8", "replace")
        return ProcessOutput(completed.returncode, stdout, stderr)

    @staticmethod
    def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
        command = tuple(str(part) for part in argv)
        if not command or not command[0].strip():
            raise ValueError("worker requires a non-empty argv")
        if any("\x00" in part for part in command):
            raise ValueError("argv cannot contain NUL bytes")
        return command

    def _publish(self, job: WorkerJob, event_type: str, payload: dict[str, object]) -> None:
        from datetime import datetime, timezone

        self.events.publish(
            Event(
                event_id=f"job_{job.job_id}_{event_type}_{job.attempt}",
                mission_id=job.mission_id,
                event_type=event_type,
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                payload={"job_id": job.job_id, **payload},
            )
        )
