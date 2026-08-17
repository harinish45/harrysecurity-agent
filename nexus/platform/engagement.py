"""Canonical authorized engagement package for planning, policy, audit and reports.

This object is declarative: it does not execute against targets. Execution must
consume the package through the existing authorization, scope, approval and
sandbox controls.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json

from nexus.platform.capabilities import WorkflowMode


@dataclass(frozen=True)
class EngagementRules:
    authorization_reference: str
    allowed_targets: tuple[str, ...]
    excluded_targets: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    excluded_tools: tuple[str, ...] = ()
    allowed_techniques: tuple[str, ...] = ()
    excluded_techniques: tuple[str, ...] = ()
    max_concurrency: int = 1
    max_requests_per_minute: int = 60
    destructive_actions: str = "deny"
    approval_mode: str = "critical_only"
    data_handling: str = "confidential"
    cleanup_required: bool = True
    abort_on_scope_violation: bool = True

    def validate(self) -> None:
        if not self.authorization_reference.strip():
            raise ValueError("authorization_reference is required")
        if not self.allowed_targets:
            raise ValueError("at least one allowed target is required")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if self.max_requests_per_minute < 1:
            raise ValueError("max_requests_per_minute must be >= 1")
        if self.destructive_actions not in {"deny", "approval_required", "allowed"}:
            raise ValueError("invalid destructive_actions policy")
        if self.approval_mode not in {"none", "critical_only", "every_high_impact", "fully_interactive"}:
            raise ValueError("invalid approval_mode")


@dataclass(frozen=True)
class EngagementPackage:
    engagement_id: str
    name: str
    assessment_mode: WorkflowMode
    objectives: tuple[str, ...]
    rules: EngagementRules
    threat_profile: str = "standard"
    conops: str = ""
    deconfliction_plan: str = ""
    contact_plan: str = ""
    abort_criteria: tuple[str, ...] = ()
    cleanup_plan: str = ""
    attack_objectives: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.engagement_id.strip():
            raise ValueError("engagement_id is required")
        if not self.name.strip():
            raise ValueError("name is required")
        if not self.objectives:
            raise ValueError("at least one objective is required")
        self.rules.validate()
        if self.rules.cleanup_required and not self.cleanup_plan.strip():
            raise ValueError("cleanup_plan is required when cleanup is enabled")
        if self.rules.abort_on_scope_violation and not self.abort_criteria:
            raise ValueError("abort_criteria required when scope violations abort the engagement")

    def canonical(self) -> dict[str, object]:
        self.validate()
        return {
            "engagement_id": self.engagement_id,
            "name": self.name,
            "assessment_mode": self.assessment_mode.value,
            "objectives": list(self.objectives),
            "rules": {
                "authorization_reference": self.rules.authorization_reference,
                "allowed_targets": list(self.rules.allowed_targets),
                "excluded_targets": list(self.rules.excluded_targets),
                "allowed_tools": list(self.rules.allowed_tools),
                "excluded_tools": list(self.rules.excluded_tools),
                "allowed_techniques": list(self.rules.allowed_techniques),
                "excluded_techniques": list(self.rules.excluded_techniques),
                "max_concurrency": self.rules.max_concurrency,
                "max_requests_per_minute": self.rules.max_requests_per_minute,
                "destructive_actions": self.rules.destructive_actions,
                "approval_mode": self.rules.approval_mode,
                "data_handling": self.rules.data_handling,
                "cleanup_required": self.rules.cleanup_required,
                "abort_on_scope_violation": self.rules.abort_on_scope_violation,
            },
            "threat_profile": self.threat_profile,
            "conops": self.conops,
            "deconfliction_plan": self.deconfliction_plan,
            "contact_plan": self.contact_plan,
            "abort_criteria": list(self.abort_criteria),
            "cleanup_plan": self.cleanup_plan,
            "attack_objectives": list(self.attack_objectives),
            "mitre_techniques": list(self.mitre_techniques),
        }

    def canonical_json(self) -> str:
        return json.dumps(self.canonical(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def package_hash(self) -> str:
        return sha256(self.canonical_json().encode("utf-8")).hexdigest()
