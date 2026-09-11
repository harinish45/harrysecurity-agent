"""
NEXUS-STRIKE — free-tier LLM provider policy.

Classifies each of LLMRouter's 10 providers as genuinely free-to-use or
paid, and provides the NEXUS_FREE_TIER_ONLY gate that LLMRouter consults
so the whole platform can run at zero LLM cost when a user wants that —
provider selection AND fallback both stay inside the free set, rather than
silently sliding onto a paid provider just because it happens to have a
key configured.

Classification (verified against each provider's actual real-world
pricing model, not assumed from the name):
  - ollama:     always free — runs locally, no API key, no network cost.
  - groq:       has a real free tier (generous rate limits, no card
                required for the free tier this session verified live).
  - nvidia:     NVIDIA NIM (build.nvidia.com) issues free-tier API keys
                (community access, no card) for OpenAI-compatible
                inference — free until a paid NIM deployment is chosen.
  - openrouter: hosts models with an explicit `:free` suffix that cost
                nothing and need no payment method — but the SAME
                provider also proxies fully paid models under other
                slugs. Free-tier-safe only when the configured model
                actually carries `:free` — see `openrouter_model_is_free`.
  - omniroute:  documented in this repo's own .env as "Free token —
                OpenAI-compatible" — treated as free by configuration
                intent, not independently verified (no live key here).
  - custom:     points at whatever OpenAI-compatible endpoint the user
                configures (could be a local LM Studio/Ollama-compatible
                server = free, or a paid gateway) — genuinely ambiguous,
                so it is NOT included in the free set by default; a user
                who knows their custom endpoint is free can still select
                it explicitly (NEXUS_FREE_TIER_ONLY only restricts
                *automatic* selection/fallback, not an explicit choice).
  - deepseek:   no free tier — pay-per-token from the first call.
  - openai:     no free tier for API access — pay-per-token.
  - anthropic:  no free tier for API access — pay-per-token.
  - azure:      Azure OpenAI is a paid enterprise offering.
"""
from __future__ import annotations

import os

# Priority order: local-first, then the providers with the most generous
# real free tiers, ending with the ones that are free-by-configuration but
# unverified in this environment.
FREE_TIER_PROVIDERS: list[str] = ["ollama", "groq", "nvidia", "openrouter", "omniroute"]

PAID_PROVIDERS: list[str] = ["openai", "anthropic", "azure", "deepseek"]

# Provider whose free-ness depends entirely on what the user points it at.
# Never auto-selected/auto-fallen-back-to under NEXUS_FREE_TIER_ONLY, but
# not treated as "paid" either — an explicit `provider="custom"` still
# works if the user knows their own endpoint is free.
AMBIGUOUS_PROVIDERS: list[str] = ["custom"]


def is_free_tier_provider(name: str) -> bool:
    return name in FREE_TIER_PROVIDERS


def free_tier_only_enabled() -> bool:
    """True when NEXUS_FREE_TIER_ONLY is set to a truthy value."""
    return os.getenv("NEXUS_FREE_TIER_ONLY", "").strip().lower() in ("1", "true", "yes", "on")


def openrouter_model_is_free(model: str | None) -> bool:
    """OpenRouter proxies both free and paid models under the same provider
    name — a model slug is only actually free if it carries the `:free`
    suffix OpenRouter uses to mark zero-cost models."""
    return bool(model) and model.strip().endswith(":free")
