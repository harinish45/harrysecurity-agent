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


class ToolProfileError(ValueError):
    """Raised when legacy registry metadata cannot be turned into a valid
    ToolProfile. Kept distinct from a bare ValueError so callers (e.g.
    ToolRegistry.register) can catch it specifically without also
    swallowing unrelated ValueErrors raised deeper in tool construction."""


def profile_from_metadata(name: str, metadata: dict) -> ToolProfile:
    """Build a safe profile from legacy registry metadata.

    risk_level is deliberately NOT defensively coerced to a default on a bad
    value: silently downgrading an unparseable risk_level to "low" would
    under-declare risk for what may genuinely be a dangerous tool, bypassing
    guardrail/scheduling decisions that key off it. A malformed risk_level
    fails loud (ToolProfileError) instead. timeout_seconds/max_concurrency
    are pure scheduling knobs with no security meaning, so a malformed value
    there safely falls back to the field default rather than taking down
    registration of every other tool in a 260+-tool registry.
    """
    profile = metadata.get("profile")
    if isinstance(profile, ToolProfile):
        try:
            profile.validate()
        except ValueError as exc:
            raise ToolProfileError(f"tool '{name}': {exc}") from exc
        return profile

    try:
        risk_level = RiskLevel(str(metadata.get("risk_level", "low")))
    except ValueError as exc:
        raise ToolProfileError(
            f"tool '{name}': invalid risk_level {metadata.get('risk_level')!r}"
        ) from exc

    try:
        timeout_seconds = int(metadata.get("timeout_seconds", 300))
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
    except (TypeError, ValueError):
        timeout_seconds = 300

    try:
        max_concurrency = int(metadata.get("max_concurrency", 1))
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
    except (TypeError, ValueError):
        max_concurrency = 1

    try:
        tags = tuple(str(tag) for tag in metadata.get("tags", ()))
    except TypeError:
        tags = ()

    try:
        return ToolProfile(
            name=name,
            domain=str(metadata.get("domain", name.split(".")[0] if "." in name else "unknown")),
            risk_level=risk_level,
            timeout_seconds=timeout_seconds,
            max_concurrency=max_concurrency,
            tags=tags,
        )
    except ValueError as exc:
        raise ToolProfileError(f"tool '{name}': {exc}") from exc
