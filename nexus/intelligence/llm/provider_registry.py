"""Provider-agnostic LLM routing policy for NEXUS-STRIKE.

Secrets remain outside this registry. The registry exposes only safe metadata
for the planner and UI; runtime credentials continue to come from settings or
an approved secret store.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class ModelClass(str, Enum):
    FAST = "fast"
    REASONING = "reasoning"
    CODING = "coding"
    VISION = "vision"
    LOCAL = "local"


@dataclass(frozen=True)
class ProviderProfile:
    provider_id: str
    display_name: str
    model: str
    model_class: ModelClass = ModelClass.REASONING
    base_url: str = ""
    enabled: bool = True
    local: bool = False
    supports_tools: bool = True
    supports_json: bool = True
    privacy_tier: str = "standard"
    cost_tier: str = "standard"
    tags: tuple[str, ...] = ()

    def public_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "model": self.model,
            "model_class": self.model_class.value,
            "base_url": self.base_url,
            "enabled": self.enabled,
            "local": self.local,
            "supports_tools": self.supports_tools,
            "supports_json": self.supports_json,
            "privacy_tier": self.privacy_tier,
            "cost_tier": self.cost_tier,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class RoutingPolicy:
    preferred_provider: str
    fallback_providers: tuple[str, ...] = ()
    require_local: bool = False
    require_tools: bool = True
    max_cost_tier: str = "premium"


class ProviderRegistry:
    """Deterministic provider catalogue and policy resolver."""

    def __init__(self, profiles: Iterable[ProviderProfile] = ()) -> None:
        self._profiles = {profile.provider_id: profile for profile in profiles}

    def register(self, profile: ProviderProfile) -> None:
        self._profiles[profile.provider_id] = profile

    def get(self, provider_id: str) -> ProviderProfile:
        return self._profiles[provider_id]

    def resolve(self, policy: RoutingPolicy) -> tuple[ProviderProfile, ...]:
        candidates = (policy.preferred_provider, *policy.fallback_providers)
        resolved: list[ProviderProfile] = []
        for provider_id in candidates:
            profile = self._profiles.get(provider_id)
            if profile is None or not profile.enabled:
                continue
            if policy.require_local and not profile.local:
                continue
            if policy.require_tools and not profile.supports_tools:
                continue
            resolved.append(profile)
        return tuple(resolved)

    def public_catalogue(self) -> list[dict[str, object]]:
        return [
            profile.public_dict()
            for profile in sorted(self._profiles.values(), key=lambda item: item.provider_id)
        ]
