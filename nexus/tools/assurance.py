"""Tool assurance and bounded self-improvement primitives.

Runtime telemetry may produce recommendations, but no recommendation can
silently change authorization, scope, risk limits, credentials, or execution
policy. Those controls remain explicit control-plane decisions.
"""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from statistics import median
from typing import Iterable, Mapping, Sequence

from nexus.tools.profile import ToolProfile

# A tool that unconditionally raises (a stub, a broken import, a signature
# that can't accept the framework's calling convention) must not be reported
# "healthy" just because it's a Python callable — see audit() below. The
# probe target is an inert, local-only value; it does not authorize or imply
# a live engagement against any external host. Kept module-level (not a
# fresh pool per audit() call, and never explicitly shut down) for the same
# reason nexus.tools.executor keeps a shared pool: `future.result(timeout=…)`
# lets audit() give up on a hung tool without blocking forever, but Python
# has no safe way to kill a wedged thread — a tool that never returns leaks
# one worker thread rather than stalling the whole audit.
_PROBE_TARGET = "127.0.0.1"
_PROBE_TIMEOUT_SECONDS = 5.0
_PROBE_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="nexus-tool-assurance-probe"
)


@dataclass(frozen=True)
class ToolCheck:
    name: str
    callable_ok: bool
    profile_ok: bool
    schema_ok: bool
    issues: tuple[str, ...] = ()

    @property
    def healthy(self) -> bool:
        return self.callable_ok and self.profile_ok and self.schema_ok and not self.issues


@dataclass(frozen=True)
class ToolObservation:
    tool_name: str
    success: bool
    duration_seconds: float
    timed_out: bool = False
    evidence_count: int = 0
    finding_count: int = 0

    def __post_init__(self) -> None:
        if self.duration_seconds < 0:
            raise ValueError("duration_seconds cannot be negative")
        if self.evidence_count < 0 or self.finding_count < 0:
            raise ValueError("result counts cannot be negative")


@dataclass(frozen=True)
class ImprovementRecommendation:
    tool_name: str
    kind: str
    rationale: str
    confidence: float
    proposed_change: Mapping[str, object]
    requires_approval: bool = True


@dataclass(frozen=True)
class ToolAssurance:
    protected_fields: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"risk", "credentials", "scope", "authorization", "allowed_targets"}
        )
    )

    def audit(self, tools: Mapping[str, object], profiles: Mapping[str, ToolProfile]) -> tuple[ToolCheck, ...]:
        checks: list[ToolCheck] = []
        for name in sorted(tools):
            fn = tools[name]
            issues: list[str] = []
            callable_ok = callable(fn)
            profile_ok = name in profiles
            schema_ok = False
            if not callable_ok:
                issues.append("registered object is not callable")
            else:
                # `callable(fn)` only proves `fn` is a Python callable — it says
                # nothing about whether calling it actually works. Without this,
                # a tool that unconditionally raises on every real call (a stub,
                # a broken import, a signature that can't accept the framework's
                # `target=`/`**kwargs` convention) is reported healthy purely
                # because it exists, which is exactly the false-assurance signal
                # this audit exists to catch. Probe it with a real, bounded call.
                probe_issue = self._probe_invocation(fn)
                if probe_issue is not None:
                    callable_ok = False
                    issues.append(probe_issue)
            if not profile_ok:
                issues.append("missing execution profile")
            else:
                try:
                    payload = profiles[name].to_dict()
                    schema_ok = isinstance(payload, dict) and bool(payload.get("name"))
                except Exception as exc:
                    issues.append(f"profile serialization failed: {type(exc).__name__}")
            checks.append(ToolCheck(name, callable_ok, profile_ok, schema_ok, tuple(issues)))
        return tuple(checks)

    @staticmethod
    def _probe_invocation(fn: object) -> str | None:
        """Actually call `fn` with the framework's calling convention
        (`target=<inert local probe>`) and report what went wrong, or None
        if the call behaved like a registered NEXUS-STRIKE tool must:
        returning (not raising) a dict-shaped result within a bounded time.

        This deliberately does not inspect *what* the tool reported — a
        tool returning `status: failed` for a bogus/unreachable target is
        working correctly (see nexus.tools.executor's "truthful statuses"
        contract). What it must never do is raise, hang, or hand back
        something that isn't the agreed result shape.
        """
        future = _PROBE_POOL.submit(fn, target=_PROBE_TARGET)
        try:
            result = future.result(timeout=_PROBE_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            return f"tool invocation did not return within {_PROBE_TIMEOUT_SECONDS}s"
        except Exception as exc:
            return f"tool invocation raised {type(exc).__name__}: {exc}"
        if not isinstance(result, dict):
            return f"tool invocation returned {type(result).__name__}, not a dict"
        return None

    def recommend(self, observations: Sequence[ToolObservation]) -> tuple[ImprovementRecommendation, ...]:
        grouped: dict[str, list[ToolObservation]] = {}
        for observation in observations:
            grouped.setdefault(observation.tool_name, []).append(observation)
        recommendations: list[ImprovementRecommendation] = []
        for name, samples in sorted(grouped.items()):
            if len(samples) < 5:
                continue
            timeout_rate = sum(item.timed_out for item in samples) / len(samples)
            success_rate = sum(item.success for item in samples) / len(samples)
            median_duration = median(item.duration_seconds for item in samples)
            if timeout_rate >= 0.30:
                recommendations.append(
                    ImprovementRecommendation(
                        name, "timeout-review",
                        "At least 30% of recent executions timed out.",
                        min(1.0, 0.60 + timeout_rate), {"timeout_multiplier": 1.25},
                    )
                )
            elif success_rate >= 0.95 and median_duration > 0:
                recommendations.append(
                    ImprovementRecommendation(
                        name, "performance-observation",
                        "Recent executions are highly reliable; review timeout/concurrency using measured latency.",
                        min(1.0, success_rate), {"median_duration_seconds": round(median_duration, 3)},
                    )
                )
            if sum(item.evidence_count for item in samples) == 0 and success_rate >= 0.80:
                recommendations.append(
                    ImprovementRecommendation(
                        name, "evidence-contract-review",
                        "Successful executions produce no recorded evidence; verify the adapter/output contract.",
                        success_rate, {"expected_evidence": "review-required"},
                    )
                )
        return tuple(recommendations)

    def approved_changes(self, recommendations: Iterable[ImprovementRecommendation]) -> tuple[ImprovementRecommendation, ...]:
        safe: list[ImprovementRecommendation] = []
        for recommendation in recommendations:
            if any(field in recommendation.proposed_change for field in self.protected_fields):
                continue
            safe.append(recommendation)
        return tuple(safe)
