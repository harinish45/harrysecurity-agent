"""Worker contracts for durable, isolated mission execution."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from nexus.agents.capabilities import RiskLevel


class WorkerState(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class WorkerJob:
    job_id: str
    mission_id: str
    task_id: str
    capability: str
    target_scope: tuple[str, ...]
    risk_level: RiskLevel = RiskLevel.LOW
    timeout_seconds: int = 300
    attempt: int = 1

    def validate(self) -> None:
        if not self.job_id or not self.mission_id or not self.task_id:
            raise ValueError("job, mission, and task identifiers are required")
        if not self.target_scope:
            raise ValueError("worker job requires explicit target scope")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        if self.attempt < 1:
            raise ValueError("attempt must be positive")


class Worker(Protocol):
    def execute(self, job: WorkerJob) -> WorkerState:
        ...


@dataclass(frozen=True)
class WorkerResult:
    job_id: str
    state: WorkerState
    evidence_ids: tuple[str, ...] = ()
    error: str = ""
