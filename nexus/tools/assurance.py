"""Tool assurance and bounded self-improvement primitives.

This module deliberately separates *learning* from *changing policy*. Runtime
telemetry may produce recommendations, but no recommendation can silently
change authorization, scope, risk limits, credentials, or execution policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median
from typing import Iterable, Mapping, Sequence

from nexus.tools.profile import ToolProfile


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
    """A privacy-safe execution observation used for recommendations."""

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


@dataclass
class ToolAssurance:
    """Validate registered tool contracts and generate bounded recommendations."""

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
            if not profile_ok:
                issues.append("missing execution profile")
            else:
                try:
                    payload = profiles[name].to_dict()
                    schema_ok = isinstance(payload, dict) and bool(payload.get("name"))
                except Exception as exc:  # pragma: no cover - defensive boundary
                    issues.append(f"profile serialization failed: {type(exc).__name__}")
            checks.append(ToolCheck(name, callable_ok, profile_ok, schema_ok, tuple(issues)))
        return tuple(checks)

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
                        name,
                        "timeout-review",
                        "At least 30% of recent executions timed out.",
                        min(1.0, 0.60 + timeout_rate),
                        {"timeout_multiplier": 1.25},
                    )
                )
            elif success_rate >= 0.95 and median_duration > 0:
                recommendations.append(
                    ImprovementRecommendation(
                        name,
                        "performance-observation",
                        "Recent executions are highly reliable; review the timeout/concurrency profile using measured latency.",
                        min(1.0, success_rate),
                        {"median_duration_seconds": round(median_duration, 3)},
                    )
                )
            if sum(item.evidence_count for item in samples) == 0 and success_rate >= 0.80:
                recommendations.append(
                    ImprovementRecommendation(
                        name,
                        "evidence-contract-review",
                        "Successful executions are producing no recorded evidence; verify the adapter/output contract.",
                        success_rate,
                        {"expected_evidence": "review-required"},
                    )
                )
        return tuple(recommendations)

    def approved_changes(self, recommendations: Iterable[ImprovementRecommendation]) -> tuple[ImprovementRecommendation, ...]:
        """Return only recommendations safe to present for explicit review.

        Protected policy fields can never be auto-applied by this module.
        """
        safe: list[ImprovementRecommendation] = []
        for recommendation in recommendations:
            if any(field in recommendation.proposed_change for field in self.protected_fields):
                continue
            safe.append(recommendation)
        return tuple(safe)
