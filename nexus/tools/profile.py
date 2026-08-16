"""Typed execution profiles for NEXUS-STRIKE tools.

Profiles describe how a tool should be scheduled and observed. They are not an
authorization decision; policy and scope guards remain authoritative upstream.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from nexus.agents.capabilities import RiskLevel


class ResourceClass(str, Enum):
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    DISK = "disk"
    GPU = "gpu"
    HARDWARE = "hardware"


class ReliabilityClass(str, Enum):
    DETERMINISTIC = "deterministic"
    EVENTUAL = "eventual"
    BEST_EFFORT = "best_effort"


@dataclass(frozen=True)
class ToolProfile:
    """Operational contract consumed by scheduling, routing and telemetry."""

    name: str
    domain: str
    capabilities: tuple[str, ...] = ()
    risk_level: RiskLevel = RiskLevel.LOW
    resource_class: ResourceClass = ResourceClass.NETWORK
    reliability: ReliabilityClass = ReliabilityClass.BEST_EFFORT
    timeout_seconds: int = 300
    max_concurrency: int = 1
    rate_limit_per_minute: int | None = None
    requires_network: bool = False
    requires_credentials: bool = False
    requires_hardware: bool = False
    supports_parallel: bool = False
    supports_resume: bool = False
    supports_dry_run: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("tool profile requires a name")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        if self.rate_limit_per_minute is not None and self.rate_limit_per_minute < 1:
            raise ValueError("rate_limit_per_minute must be positive")
        if self.requires_hardware and self.resource_class is not ResourceClass.HARDWARE:
            raise ValueError("hardware-dependent tools must use hardware resource class")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "name": self.name,
            "domain": self.domain,
            "capabilities": list(self.capabilities),
            "risk_level": self.risk_level.value,
            "resource_class": self.resource_class.value,
            "reliability": self.reliability.value,
            "timeout_seconds": self.timeout_seconds,
            "max_concurrency": self.max_concurrency,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "requires_network": self.requires_network,
            "requires_credentials": self.requires_credentials,
            "requires_hardware": self.requires_hardware,
            "supports_parallel": self.supports_parallel,
            "supports_resume": self.supports_resume,
            "supports_dry_run": self.supports_dry_run,
            "tags": list(self.tags),
        }


def profile_from_metadata(name: str, metadata: dict) -> ToolProfile:
    """Build a safe profile from legacy registry metadata."""
    profile = metadata.get("profile")
    if isinstance(profile, ToolProfile):
        profile.validate()
        return profile
    return ToolProfile(
        name=name,
        domain=str(metadata.get("domain", name.split(".")[0] if "." in name else "unknown")),
        risk_level=RiskLevel(str(metadata.get("risk_level", "low"))),
        timeout_seconds=int(metadata.get("timeout_seconds", 300)),
        max_concurrency=int(metadata.get("max_concurrency", 1)),
        tags=tuple(str(tag) for tag in metadata.get("tags", ())),
    )
