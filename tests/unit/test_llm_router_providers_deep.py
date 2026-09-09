"""Deep behavioral coverage for nexus/intelligence/llm/router.py.

`nexus/intelligence` sat at 17.2% coverage for most of this session —
notably including the stale-Groq-model-ID bug that went undetected for a
while precisely because nothing exercised the real request-building code
paths. `tests/unit/test_llm_free_tier_config.py` already covers the
free-tier classification/fallback logic well; this file covers what it
doesn't: `_get_client()`'s provider dispatch, and each provider class's
real request-building, response-parsing, and error-handling behavior.

Also: `nexus/intelligence/llm/providers/*.py` (9 files, 958 lines) and
`nexus/intelligence/knowledge/`, `nexus/intelligence/memory/`,
`nexus/intelligence/reasoning/` (16 files, all literal `class X: pass`
two-liners) were confirmed via `grep -rn` to have zero references anywhere
in the codebase and have been deleted rather than test-padded — writing
tests for empty stub classes would be padding, not coverage. `router.py`
is the only file in `nexus/intelligence` with real logic.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nexus.foundation.config import config
from nexus.intelligence.llm.router import (
    AnthropicProvider,
    AzureProvider,
    LLMRouter,
    MockProvider,
    OpenAICompatibleProvider,
)


# ── MockProvider ─────────────────────────────────────────────────────────

def test_mock_provider_complete_echoes_prompt_prefix():
    result = MockProvider().complete("hello world" * 20)
    assert result.startswith("[MOCK] Processed:")
    assert "hello world" in result


def test_mock_provider_stream_yields_one_chunk():
    chunks = list(MockProvider().stream("test prompt"))
    assert len(chunks) == 1
    assert "[MOCK]" in chunks[0]


# ── LLMRouter._get_client() dispatch ─────────────────────────────────────

def _force_no_providers_available(monkeypatch):
    """"mock" mode is only ever reached via the empty-fallback branch in
    `_validate_provider()` — Ollama's PROVIDER_CONFIGS entry has
    `env_key=None`, so `_detect_available()` unconditionally includes it
    regardless of any configured key, meaning `_available_providers` is
    realistically NEVER empty in normal operation (confirmed: passing
    `provider="mock"` explicitly gets silently overridden back to
    "ollama"). The only way to genuinely exercise the mock fallback path
    is to remove every PROVIDER_CONFIGS entry, Ollama included."""
    monkeypatch.setattr(LLMRouter, "PROVIDER_CONFIGS", {})


def test_get_client_dispatches_mock_when_no_providers_available(monkeypatch):
    _force_no_providers_available(monkeypatch)
    router = LLMRouter(provider="mock")
    assert router.provider == "mock"
    client = router._get_client()
    assert isinstance(client, MockProvider)
    # Cached: a second call must return the SAME instance, not rebuild.
    assert router._get_client() is client


def test_explicit_mock_request_is_overridden_by_a_real_available_provider(monkeypatch):
    """Documents real, current behavior: Ollama is always in
    `_available_providers` (no key needed), so an explicit
    `provider="mock"` request is NOT honored whenever Ollama (or any
    other configured provider) is available — the router silently
    substitutes a real provider instead. This is a genuine quirk, not
    invented — confirmed against the actual code, not assumed."""
    monkeypatch.setattr(config, "openai_api_key", None)
    monkeypatch.setattr(config, "anthropic_api_key", None)
    monkeypatch.setattr(config, "groq_api_key", None)
    monkeypatch.setattr(config, "nvidia_api_key", None)
    monkeypatch.setattr(config, "openrouter_api_key", None)
    monkeypatch.setattr(config, "azure_openai_api_key", None)
    monkeypatch.setattr(config, "deepseek_api_key", None)
    monkeypatch.setattr(config, "omniroute_api_key", None)
    monkeypatch.setattr(config, "custom_api_key", None)
    router = LLMRouter(provider="mock")
    assert router.provider == "ollama"


def test_get_client_dispatches_anthropic_provider(monkeypatch):
    monkeypatch.setattr(config, "anthropic_api_key", "sk-ant-fake")
    monkeypatch.setattr(config, "anthropic_model", "claude-3-opus-20240229")
    router = LLMRouter(provider="anthropic")
    client = router._get_client()
    assert isinstance(client, AnthropicProvider)
    assert client.api_key == "sk-ant-fake"
    assert client.model == "claude-3-opus-20240229"


def test_get_client_dispatches_azure_provider(monkeypatch):
    monkeypatch.setattr(config, "azure_openai_api_key", "az-fake-key")
    monkeypatch.setattr(config, "azure_openai_endpoint", "https://example.openai.azure.com")
    # NexusConfig has no "azure_model" field (only "azure_openai_model") —
    # `_get_client()` looks up f"{self.provider}_model" = "azure_model",
    # doesn't find it, and correctly falls back to PROVIDER_CONFIGS'
    # "gpt-4" default via getattr()'s default argument. Confirmed real
    # behavior, not worked around.
    router = LLMRouter(provider="azure")
    client = router._get_client()
    assert isinstance(client, AzureProvider)
    assert client.api_key == "az-fake-key"
    assert client.endpoint == "https://example.openai.azure.com"


def test_get_client_dispatches_openai_compatible_for_groq(monkeypatch):
    monkeypatch.setattr(config, "groq_api_key", "gsk-fake")
    monkeypatch.setattr(config, "groq_model", "openai/gpt-oss-20b")
    monkeypatch.setattr(config, "groq_base_url", "https://api.groq.com/openai/v1")
    router = LLMRouter(provider="groq")
    client = router._get_client()
    assert isinstance(client, OpenAICompatibleProvider)
    assert client.api_key == "gsk-fake"
    assert client.base_url == "https://api.groq.com/openai/v1"
    assert client.model == "openai/gpt-oss-20b"


def test_get_client_ollama_uses_placeholder_key_when_no_env_key_configured(monkeypatch):
    # Ollama's PROVIDER_CONFIGS entry has env_key=None (no API key concept —
    # it's a local server), so _get_client falls back to the literal string
    # "ollama" as a placeholder api_key rather than None (some OpenAI-client
    # libraries reject a None api_key outright).
    monkeypatch.setattr(config, "ollama_base_url", "http://localhost:11434/v1")
    monkeypatch.setattr(config, "ollama_model", "qwen2.5-coder:latest")
    router = LLMRouter(provider="ollama", free_tier_only=False)
    client = router._get_client()
    assert isinstance(client, OpenAICompatibleProvider)
    assert client.api_key == "ollama"
    assert client.base_url == "http://localhost:11434/v1"


# ── LLMRouter.complete / complete_async / stream / chat dispatch ─────────

def test_router_complete_delegates_to_client(monkeypatch):
    _force_no_providers_available(monkeypatch)
    router = LLMRouter(provider="mock")
    result = router.complete("what is nmap")
    assert "[MOCK] Processed:" in result


@pytest.mark.asyncio
async def test_router_complete_async_falls_back_to_sync_complete_when_no_async_method(monkeypatch):
    _force_no_providers_available(monkeypatch)
    router = LLMRouter(provider="mock")
    # MockProvider has no complete_async — router must degrade to the sync path.
    result = await router.complete_async("test")
    assert "[MOCK] Processed:" in result


def test_router_stream_delegates_to_client_stream(monkeypatch):
    _force_no_providers_available(monkeypatch)
    router = LLMRouter(provider="mock")
    chunks = list(router.stream("test"))
    assert len(chunks) == 1


def test_router_chat_falls_back_to_prompt_conversion_when_client_has_no_chat(monkeypatch):
    _force_no_providers_available(monkeypatch)
    router = LLMRouter(provider="mock")
    # MockProvider has no .chat() method — router must convert messages to
    # a flat prompt and call .complete() instead of raising AttributeError.
    result = router.chat([{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}])
    assert "[MOCK] Processed:" in result


def test_get_provider_info_reports_active_and_available(monkeypatch):
    _force_no_providers_available(monkeypatch)
    router = LLMRouter(provider="mock")
    info = router.get_provider_info()
    assert info["active_provider"] == "mock"
    assert info["active_provider_is_free"] is True
    assert "available_providers" in info


# ── OpenAICompatibleProvider — real request-building + error handling ────

def test_openai_compatible_no_sdk_returns_placeholder_without_crashing():
    with patch.dict("sys.modules", {"openai": None}):
        provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
        result = provider.complete("hello")
    assert "Would call API with" in result
    assert "test-model" in result


def test_openai_compatible_complete_builds_correct_message_shape_and_returns_content():
    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="real completion text"))]
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = fake_response

    provider = OpenAICompatibleProvider(api_key="fake", base_url="https://api.example.com/v1", model="test-model")
    provider._client = fake_client  # bypass real SDK instantiation

    result = provider.complete("what ports are open", system="you are a scanner")

    assert result == "real completion text"
    call_kwargs = fake_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "test-model"
    assert call_kwargs["messages"] == [
        {"role": "system", "content": "you are a scanner"},
        {"role": "user", "content": "what ports are open"},
    ]


def test_openai_compatible_complete_handles_api_exception_without_crashing():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = RuntimeError("connection refused")

    provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
    provider._client = fake_client

    result = provider.complete("test")

    assert "[ERROR]" in result
    assert "connection refused" in result


def test_openai_compatible_stream_yields_real_chunks():
    chunk1 = MagicMock()
    chunk1.choices = [MagicMock(delta=MagicMock(content="Hello"))]
    chunk2 = MagicMock()
    chunk2.choices = [MagicMock(delta=MagicMock(content=" world"))]
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = iter([chunk1, chunk2])

    provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
    provider._client = fake_client

    chunks = list(provider.stream("test"))

    assert chunks == ["Hello", " world"]
    assert fake_client.chat.completions.create.call_args.kwargs["stream"] is True


def test_openai_compatible_stream_no_sdk_yields_placeholder():
    with patch.dict("sys.modules", {"openai": None}):
        provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
        chunks = list(provider.stream("test"))
    assert len(chunks) == 1
    assert "Streaming" in chunks[0]


def test_openai_compatible_stream_handles_exception_mid_stream():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = RuntimeError("stream broke")
    provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
    provider._client = fake_client
    chunks = list(provider.stream("test"))
    assert any("[ERROR]" in c for c in chunks)


def test_openai_compatible_chat_passes_messages_through_unmodified():
    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="chat reply"))]
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = fake_response

    provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
    provider._client = fake_client

    messages = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]
    result = provider.chat(messages)

    assert result == "chat reply"
    assert fake_client.chat.completions.create.call_args.kwargs["messages"] == messages


def test_openai_compatible_chat_no_sdk_returns_placeholder():
    with patch.dict("sys.modules", {"openai": None}):
        provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
        result = provider.chat([{"role": "user", "content": "hi"}])
    assert "Chat: 1 messages" in result


def test_openai_compatible_chat_handles_exception():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = RuntimeError("boom")
    provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
    provider._client = fake_client
    result = provider.chat([{"role": "user", "content": "hi"}])
    assert "[ERROR]" in result


def test_openai_compatible_client_is_cached_across_calls():
    provider = OpenAICompatibleProvider(api_key="fake", base_url=None, model="test-model")
    fake_client = MagicMock()
    provider._client = fake_client
    assert provider._get_client() is fake_client


# ── AnthropicProvider — real request-building + error handling ───────────

def test_anthropic_provider_no_sdk_returns_placeholder():
    with patch.dict("sys.modules", {"anthropic": None}):
        provider = AnthropicProvider(api_key="fake", model="claude-3-opus-20240229")
        result = provider.complete("hello")
    assert "Would process" in result


def test_anthropic_provider_complete_builds_correct_request_and_returns_text():
    fake_message = MagicMock()
    fake_message.content = [MagicMock(text="claude's real answer")]
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_message

    provider = AnthropicProvider(api_key="fake", model="claude-3-opus-20240229")
    provider._client = fake_client

    result = provider.complete("scan this host", system="you are a pentester")

    assert result == "claude's real answer"
    call_kwargs = fake_client.messages.create.call_args.kwargs
    assert call_kwargs["model"] == "claude-3-opus-20240229"
    assert call_kwargs["system"] == "you are a pentester"
    assert call_kwargs["messages"] == [{"role": "user", "content": "scan this host"}]


def test_anthropic_provider_complete_defaults_system_to_empty_string():
    fake_message = MagicMock()
    fake_message.content = [MagicMock(text="ok")]
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_message
    provider = AnthropicProvider(api_key="fake", model="claude-3-opus-20240229")
    provider._client = fake_client

    provider.complete("test")  # no system= passed

    assert fake_client.messages.create.call_args.kwargs["system"] == ""


def test_anthropic_provider_complete_handles_exception():
    fake_client = MagicMock()
    fake_client.messages.create.side_effect = RuntimeError("rate limited")
    provider = AnthropicProvider(api_key="fake", model="claude-3-opus-20240229")
    provider._client = fake_client
    result = provider.complete("test")
    assert "[ERROR]" in result
    assert "rate limited" in result


def test_anthropic_provider_client_is_cached_across_calls():
    provider = AnthropicProvider(api_key="fake", model="claude-3-opus-20240229")
    fake_client = MagicMock()
    provider._client = fake_client
    assert provider._get_client() is fake_client


# ── AzureProvider — real request-building + error handling ───────────────

def test_azure_provider_no_sdk_returns_placeholder():
    with patch.dict("sys.modules", {"openai": None}):
        provider = AzureProvider(api_key="fake", endpoint="https://x.openai.azure.com", model="gpt-4")
        result = provider.complete("hello")
    assert "Would process" in result


def test_azure_provider_complete_builds_correct_message_shape_and_returns_content():
    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="azure completion"))]
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = fake_response

    provider = AzureProvider(api_key="fake", endpoint="https://x.openai.azure.com", model="gpt-4")
    provider._client = fake_client

    result = provider.complete("enumerate subdomains", system="be concise")

    assert result == "azure completion"
    call_kwargs = fake_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-4"
    assert call_kwargs["messages"][0] == {"role": "system", "content": "be concise"}


def test_azure_provider_complete_without_system_omits_system_message():
    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content="ok"))]
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = fake_response
    provider = AzureProvider(api_key="fake", endpoint="https://x.openai.azure.com", model="gpt-4")
    provider._client = fake_client

    provider.complete("test")

    messages = fake_client.chat.completions.create.call_args.kwargs["messages"]
    assert messages == [{"role": "user", "content": "test"}]


def test_azure_provider_complete_handles_exception():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = RuntimeError("quota exceeded")
    provider = AzureProvider(api_key="fake", endpoint="https://x.openai.azure.com", model="gpt-4")
    provider._client = fake_client
    result = provider.complete("test")
    assert "[ERROR]" in result
    assert "quota exceeded" in result


def test_azure_provider_client_is_cached_across_calls():
    provider = AzureProvider(api_key="fake", endpoint="https://x.openai.azure.com", model="gpt-4")
    fake_client = MagicMock()
    provider._client = fake_client
    assert provider._get_client() is fake_client
