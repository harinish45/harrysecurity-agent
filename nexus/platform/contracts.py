"""Stable contracts shared by orchestration, execution and governance layers.

The module deliberately contains no network or shell execution. It defines
state and policy boundaries that higher layers must honor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Mapping


class CapabilityState(str, Enum):
    REGISTERED = "registered"
    CALLABLE = "callable"
    CONTRACT_VALID = "contract_valid"
    EXECUTABLE = "executable"
    EVIDENCE_VALID = "evidence_valid"
    RESULT_VALID = "result_valid"
    RELIABLE = "reliable"
    PRODUCTION_READY = "production_ready"
    BLOCKED = "blocked"


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    APPROVER = "approver"
    ADMIN = "admin"


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    actor_id: str
    role: Role
    engagement_id: str

    def can_execute(self) -> bool:
        return self.role in {Role.OPERATOR, Role.APPROVER, Role.ADMIN}

    def can_approve(self) -> bool:
        return self.role in {Role.APPROVER, Role.ADMIN}

    def can_administer(self) -> bool:
        return self.role is Role.ADMIN


@dataclass(frozen=True)
class ExecutionPolicy:
    """Non-negotiable execution boundaries.

    A learned recommendation may tune operational parameters, but it cannot
    change authorization, target scope, destructive behavior, or credential
    handling through this object.
    """

    authorized: bool
    allowed_targets: frozenset[str] = frozenset()
    destructive: bool = False
    credentials_allowed: bool = False
    max_runtime_seconds: int = 300
    rate_limit_per_minute: int = 60

    def permits(self, target: str, *, requested_destructive: bool = False) -> bool:
        if not self.authorized or target not in self.allowed_targets:
            return False
        if requested_destructive and not self.destructive:
            return False
        return self.max_runtime_seconds > 0 and self.rate_limit_per_minute > 0


@dataclass(frozen=True)
class ToolCapability:
    name: str
    version: str
    domains: tuple[str, ...]
    state: CapabilityState = CapabilityState.REGISTERED
    contract_hash: str = ""
    success_rate: float = 0.0
    evidence_rate: float = 0.0
    p95_latency_ms: float = 0.0
    observations: int = 0

    def promote(self, new_state: CapabilityState) -> "ToolCapability":
        order = list(CapabilityState)
        if new_state is CapabilityState.BLOCKED:
            return self.__class__(**{**self.__dict__, "state": new_state})
        if order.index(new_state) < order.index(self.state):
            raise ValueError(f"invalid capability regression: {self.state} -> {new_state}")
        return self.__class__(**{**self.__dict__, "state": new_state})

    def reliability_score(self) -> float:
        success = max(0.0, min(1.0, self.success_rate))
        evidence = max(0.0, min(1.0, self.evidence_rate))
        latency = 1.0 if self.p95_latency_ms <= 1000 else max(0.0, 1000 / self.p95_latency_ms)
        return round((success * 0.45) + (evidence * 0.40) + (latency * 0.15), 4)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    mission_id: str
    tool: str
    target: str
    kind: str
    confidence: float
    payload_hash: str
    provenance: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @classmethod
    def from_payload(
        cls,
        *,
        evidence_id: str,
        mission_id: str,
        tool: str,
        target: str,
        kind: str,
        payload: Mapping[str, Any],
        confidence: float,
        provenance: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
    ) -> "Evidence":
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        digest = sha256(canonical.encode()).hexdigest()
        return cls(
            evidence_id=evidence_id,
            mission_id=mission_id,
            tool=tool,
            target=target,
            kind=kind,
            confidence=max(0.0, min(1.0, confidence)),
            payload_hash=digest,
            provenance=provenance,
            tags=tags,
        )


@dataclass(frozen=True)
class MissionNode:
    node_id: str
    action: str
    dependencies: tuple[str, ...] = ()
    target: str = ""
    required_capabilities: tuple[str, ...] = ()
    status: str = "pending"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def ready(self, completed: set[str]) -> bool:
        return self.status == "pending" and all(dep in completed for dep in self.dependencies)


def execution_cache_key(tool: str, version: str, target: str, arguments: Mapping[str, Any]) -> str:
    """Stable cache/deduplication key; secrets must never be placed in arguments."""
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(f"{tool}:{version}:{target}:{canonical}".encode()).hexdigest()


PROTECTED_POLICY_FIELDS = frozenset(
    {"authorized", "allowed_targets", "destructive", "credentials_allowed"}
)
