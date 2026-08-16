"""Deterministic in-process mission job scheduler.

The scheduler owns queue semantics only. Authorization, scope, capability
selection, and actual execution remain control-plane/worker responsibilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import heapq
from threading import RLock
from time import monotonic
from typing import Callable

from nexus.runtime.workers import WorkerJob


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ScheduledJob:
    job: WorkerJob
    priority: int = 100
    state: JobState = JobState.QUEUED
    enqueued_at: float = field(default_factory=monotonic)
    retries: int = 0
    error: str = ""


class JobScheduler:
    """Bounded priority queue with cancellation and retry-safe state."""

    def __init__(self, *, max_pending: int = 256) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        self.max_pending = max_pending
        self._jobs: dict[str, ScheduledJob] = {}
        self._heap: list[tuple[int, float, str]] = []
        self._lock = RLock()

    def submit(self, job: WorkerJob, *, priority: int = 100) -> ScheduledJob:
        job.validate()
        with self._lock:
            if job.job_id in self._jobs:
                raise ValueError(f"duplicate job id: {job.job_id}")
            pending = sum(item.state is JobState.QUEUED for item in self._jobs.values())
            if pending >= self.max_pending:
                raise RuntimeError("scheduler queue is full")
            scheduled = ScheduledJob(job=job, priority=priority)
            self._jobs[job.job_id] = scheduled
            heapq.heappush(self._heap, (priority, scheduled.enqueued_at, job.job_id))
            return scheduled

    def claim(self) -> ScheduledJob | None:
        with self._lock:
            while self._heap:
                _, _, job_id = heapq.heappop(self._heap)
                current = self._jobs[job_id]
                if current.state is not JobState.QUEUED:
                    continue
                running = replace(current, state=JobState.RUNNING)
                self._jobs[job_id] = running
                return running
            return None

    def complete(self, job_id: str) -> ScheduledJob:
        return self._set_terminal(job_id, JobState.COMPLETED)

    def fail(self, job_id: str, *, error: str) -> ScheduledJob:
        return self._set_terminal(job_id, JobState.FAILED, error=error)

    def cancel(self, job_id: str) -> ScheduledJob:
        with self._lock:
            current = self._require(job_id)
            if current.state in {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}:
                return current
            cancelled = replace(current, state=JobState.CANCELLED)
            self._jobs[job_id] = cancelled
            return cancelled

    def retry(self, job_id: str) -> ScheduledJob:
        with self._lock:
            current = self._require(job_id)
            if current.state is not JobState.FAILED:
                raise ValueError("only failed jobs can be retried")
            retried_job = replace(current.job, attempt=current.job.attempt + 1)
            retried = ScheduledJob(
                job=retried_job,
                priority=current.priority,
                state=JobState.QUEUED,
                retries=current.retries + 1,
                error="",
            )
            self._jobs[job_id] = retried
            heapq.heappush(self._heap, (retried.priority, retried.enqueued_at, job_id))
            return retried

    def get(self, job_id: str) -> ScheduledJob:
        with self._lock:
            return self._require(job_id)

    def list(self, mission_id: str | None = None) -> list[ScheduledJob]:
        with self._lock:
            jobs = tuple(self._jobs.values())
        if mission_id is not None:
            jobs = tuple(item for item in jobs if item.job.mission_id == mission_id)
        return sorted(jobs, key=lambda item: (item.priority, item.enqueued_at, item.job.job_id))

    def dispatch(self, executor: Callable[[WorkerJob], object]) -> ScheduledJob | None:
        """Claim one job, invoke the executor, and normalize terminal state."""
        scheduled = self.claim()
        if scheduled is None:
            return None
        try:
            result = executor(scheduled.job)
            if getattr(result, "state", None) is not None and str(getattr(result, "state")) == "WorkerState.COMPLETED":
                return self.complete(scheduled.job.job_id)
            if getattr(result, "state", None) is not None and str(getattr(result, "state")) == "WorkerState.CANCELLED":
                return self.cancel(scheduled.job.job_id)
            return self.fail(scheduled.job.job_id, error=getattr(result, "error", "worker failed") or "worker failed")
        except Exception as exc:
            return self.fail(scheduled.job.job_id, error=str(exc))

    def _set_terminal(self, job_id: str, state: JobState, *, error: str = "") -> ScheduledJob:
        with self._lock:
            current = self._require(job_id)
            if current.state is state:
                return current
            if current.state not in {JobState.RUNNING, JobState.QUEUED}:
                raise ValueError(f"cannot transition {current.state.value} -> {state.value}")
            updated = replace(current, state=state, error=error)
            self._jobs[job_id] = updated
            return updated

    def _require(self, job_id: str) -> ScheduledJob:
        try:
            return self._jobs[job_id]
        except KeyError as exc:
            raise KeyError(f"unknown job: {job_id}") from exc
