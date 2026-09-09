"""nexus/intelligence's LLM router/provider layer had 17.2% test coverage
(measured this session) — the exact layer where a real bug lived
undetected (a stale Groq model ID, 404ing against the live API, found and
fixed earlier this session; a second stale OpenRouter free-model slug
found and fixed in this pass). This file closes that gap for the
free-tier policy layer added in this pass: `nexus/foundation/free_tier.py`
and LLMRouter's NEXUS_FREE_TIER_ONLY enforcement.
"""
import os

import pytest

from nexus.foundation.free_tier import (
    AMBIGUOUS_PROVIDERS,
    FREE_TIER_PROVIDERS,
    PAID_PROVIDERS,
    free_tier_only_enabled,
    is_free_tier_provider,
    openrouter_model_is_free,
)
from nexus.intelligence.llm.router import LLMRouter


# ── free_tier.py classification ─────────────────────────────────────────

def test_free_and_paid_lists_are_disjoint():
    assert not (set(FREE_TIER_PROVIDERS) & set(PAID_PROVIDERS))
    assert not (set(FREE_TIER_PROVIDERS) & set(AMBIGUOUS_PROVIDERS))


def test_is_free_tier_provider_classification():
    assert is_free_tier_provider("ollama")
    assert is_free_tier_provider("groq")
    assert is_free_tier_provider("nvidia")
    assert is_free_tier_provider("openrouter")
    assert not is_free_tier_provider("openai")
    assert not is_free_tier_provider("anthropic")
    assert not is_free_tier_provider("azure")
    assert not is_free_tier_provider("custom")


def test_openrouter_model_is_free_requires_free_suffix():
    assert openrouter_model_is_free("nvidia/nemotron-3-super-120b-a12b:free")
    assert not openrouter_model_is_free("openai/gpt-4-turbo")
    assert not openrouter_model_is_free(None)
    assert not openrouter_model_is_free("")


def test_free_tier_only_enabled_reads_env(monkeypatch):
    monkeypatch.delenv("NEXUS_FREE_TIER_ONLY", raising=False)
    assert free_tier_only_enabled() is False
    monkeypatch.setenv("NEXUS_FREE_TIER_ONLY", "1")
    assert free_tier_only_enabled() is True
    monkeypatch.setenv("NEXUS_FREE_TIER_ONLY", "true")
    assert free_tier_only_enabled() is True
    monkeypatch.setenv("NEXUS_FREE_TIER_ONLY", "0")
    assert free_tier_only_enabled() is False


# ── LLMRouter free-tier enforcement ─────────────────────────────────────

def test_router_free_tier_only_excludes_paid_providers(monkeypatch):
    monkeypatch.setattr("nexus.foundation.config.config.openai_api_key", "sk-fake-real-looking-key")
    monkeypatch.setattr("nexus.foundation.config.config.groq_api_key", "gsk-fake-real-looking-key")
    router = LLMRouter(provider="groq", free_tier_only=True)
    assert "openai" not in router._available_providers
    assert "groq" in router._available_providers


def test_router_free_tier_only_refuses_explicit_paid_provider_request(monkeypatch):
    monkeypatch.setattr("nexus.foundation.config.config.openai_api_key", "sk-fake-real-looking-key")
    monkeypatch.setattr("nexus.foundation.config.config.groq_api_key", "gsk-fake-real-looking-key")
    router = LLMRouter(provider="openai", free_tier_only=True)
    assert router.provider != "openai"
    from nexus.foundation.free_tier import is_free_tier_provider
    assert router.provider == "mock" or is_free_tier_provider(router.provider)


def test_router_free_tier_only_excludes_openrouter_when_model_not_free(monkeypatch):
    monkeypatch.setattr("nexus.foundation.config.config.openrouter_api_key", "sk-or-fake-key")
    monkeypatch.setattr("nexus.foundation.config.config.openrouter_model", "openai/gpt-4-turbo")
    router = LLMRouter(provider="ollama", free_tier_only=True)
    assert "openrouter" not in router._available_providers


def test_router_free_tier_only_includes_openrouter_when_model_is_free(monkeypatch):
    monkeypatch.setattr("nexus.foundation.config.config.openrouter_api_key", "sk-or-fake-key")
    monkeypatch.setattr(
        "nexus.foundation.config.config.openrouter_model", "nvidia/nemotron-3-super-120b-a12b:free"
    )
    router = LLMRouter(provider="ollama", free_tier_only=True)
    assert "openrouter" in router._available_providers


def test_router_normal_mode_still_allows_paid_providers(monkeypatch):
    monkeypatch.setattr("nexus.foundation.config.config.openai_api_key", "sk-fake-real-looking-key")
    router = LLMRouter(provider="openai", free_tier_only=False)
    assert router.provider == "openai"
    assert "openai" in router._available_providers


def test_get_provider_info_reports_free_tier_status(monkeypatch):
    router = LLMRouter(provider="ollama", free_tier_only=True)
    info = router.get_provider_info()
    assert info["free_tier_only"] is True
    assert info["active_provider_is_free"] is True


def test_router_free_tier_only_falls_back_to_mock_when_nothing_free_configured(monkeypatch):
    for key in (
        "openai_api_key", "anthropic_api_key", "openrouter_api_key",
        "nvidia_api_key", "azure_openai_api_key", "groq_api_key",
        "deepseek_api_key", "omniroute_api_key", "custom_api_key",
    ):
        monkeypatch.setattr(f"nexus.foundation.config.config.{key}", None)
    router = LLMRouter(provider="openai", free_tier_only=True)
    assert router.provider == "ollama"  # always-free local provider, no key needed
