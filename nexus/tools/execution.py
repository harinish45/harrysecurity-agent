"""Uniform execution contract for registered tools.

The contract deliberately separates tool invocation from authorization, target
scope, and worker process policy. Adapters receive already-approved structured
input and return normalized results suitable for evidence and telemetry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import monotonic
from typing import Any, Callable, Mapping, Protocol

from nexus.tools.profile import ToolProfile


class ExecutionStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True)
class ToolExecutionContext:
    mission_id: str
    job_id: str
    target_scope: tuple[str, ...]
    timeout_seconds: int
    dry_run: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolOutcome:
    status: ExecutionStatus
    started_at: float
    finished_at: float
    output: Any = None
    findings: tuple[Mapping[str, Any], ...] = ()
    evidence: tuple[Mapping[str, Any], ...] = ()
    error_class: str = ""
    error: str = ""

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.finished_at - self.started_at)


class ToolAdapter(Protocol):
    """Adapter contract for every registered capability."""

    name: str
    profile: ToolProfile

    def execute(self, context: ToolExecutionContext, arguments: Mapping[str, Any]) -> ToolOutcome:
        ...


class FunctionToolAdapter:
    """Wrap a structured Python tool function in the common execution contract."""

    def __init__(self, name: str, profile: ToolProfile, function: Callable[..., Any]) -> None:
        profile.validate()
        self.name = name
        self.profile = profile
        self._function = function

    def execute(self, context: ToolExecutionContext, arguments: Mapping[str, Any]) -> ToolOutcome:
        started = monotonic()
        try:
            result = self._function(context=context, **dict(arguments))
            status = ExecutionStatus.COMPLETED
            error_class = ""
            error = ""
        except TimeoutError as exc:
            result = None
            status = ExecutionStatus.TIMED_OUT
            error_class = type(exc).__name__
            error = str(exc)
        except Exception as exc:
            result = None
            status = ExecutionStatus.FAILED
            error_class = type(exc).__name__
            error = str(exc)
        finished = monotonic()
        return ToolOutcome(status=status, started_at=started, finished_at=finished, output=result, error_class=error_class, error=error)


def normalize_outcome(value: Any, *, started_at: float, finished_at: float) -> ToolOutcome:
    """Normalize legacy adapter results without exposing raw execution internals."""
    if isinstance(value, ToolOutcome):
        return value
    if isinstance(value, Mapping):
        findings = tuple(item for item in value.get("findings", ()) if isinstance(item, Mapping))
        evidence = tuple(item for item in value.get("evidence", ()) if isinstance(item, Mapping))
        return ToolOutcome(
            status=ExecutionStatus.COMPLETED,
            started_at=started_at,
            finished_at=finished_at,
            output=value.get("output", value),
            findings=findings,
            evidence=evidence,
        )
    return ToolOutcome(status=ExecutionStatus.COMPLETED, started_at=started_at, finished_at=finished_at, output=value)
