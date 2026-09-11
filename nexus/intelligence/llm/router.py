"""
NEXUS-STRIKE LLM Router
Routes requests to any provider: OpenAI, Anthropic, OpenRouter, Ollama, Azure, Groq, DeepSeek, Omniroute, Custom
Auto-detects available providers and falls back gracefully.
"""
import json
import os
from typing import Optional, Generator, AsyncGenerator
from nexus.foundation.config import config
from nexus.foundation.logging import logger
from nexus.foundation.free_tier import (
    free_tier_only_enabled,
    is_free_tier_provider,
    openrouter_model_is_free,
)

class LLMRouter:
    """
    Intelligent LLM router with multi-provider support.
    Auto-detects available API keys and routes requests accordingly.
    Supports streaming, async, and fallback chains.
    """

    PROVIDER_CONFIGS = {
        "openai": {
            "env_key": "openai_api_key",
            "default_model": "gpt-4-turbo",
            "base_url_key": "openai_base_url",
            "api_type": "openai",
        },
        "anthropic": {
            "env_key": "anthropic_api_key",
            "default_model": "claude-3-opus-20240229",
            "base_url_key": None,
            "api_type": "anthropic",
        },
        "openrouter": {
            "env_key": "openrouter_api_key",
            "default_model": "nvidia/nemotron-3-super-120b-a12b:free",
            "base_url_key": "openrouter_base_url",
            "api_type": "openai",
        },
        "ollama": {
            "env_key": None,
            "default_model": "qwen2.5-coder:latest",
            "base_url_key": "ollama_base_url",
            "api_type": "openai",
        },
        "nvidia": {
            "env_key": "nvidia_api_key",
            "default_model": "meta/llama-3.1-8b-instruct",
            "base_url_key": "nvidia_base_url",
            "api_type": "openai",
        },
        "azure": {
            "env_key": "azure_openai_api_key",
            "default_model": "gpt-4",
            "base_url_key": "azure_openai_endpoint",
            "api_type": "azure",
        },
        "groq": {
            "env_key": "groq_api_key",
            "default_model": "openai/gpt-oss-20b",
            "base_url_key": "groq_base_url",
            "api_type": "openai",
        },
        "deepseek": {
            "env_key": "deepseek_api_key",
            "default_model": "deepseek-chat",
            "base_url_key": "deepseek_base_url",
            "api_type": "openai",
        },
        "omniroute": {
            "env_key": "omniroute_api_key",
            "default_model": "gpt-4",
            "base_url_key": "omniroute_base_url",
            "api_type": "openai",
        },
        "custom": {
            "env_key": "custom_api_key",
            "default_model": "custom-model",
            "base_url_key": "custom_base_url",
            "api_type": "custom_api_type",
        },
    }

    def __init__(self, provider: Optional[str] = None, free_tier_only: Optional[bool] = None):
        self.provider = provider or config.llm_provider
        self._client = None
        # `free_tier_only` param lets callers opt in/out explicitly; when
        # omitted, NEXUS_FREE_TIER_ONLY decides — so the whole platform can
        # be pinned to $0 LLM cost via one env var with no code changes.
        self.free_tier_only = free_tier_only_enabled() if free_tier_only is None else free_tier_only
        self._available_providers = self._detect_available()
        self._validate_provider()

    def _is_effectively_free(self, name: str) -> bool:
        """Free-tier check that also accounts for OpenRouter's mixed
        free/paid catalog — being 'openrouter' isn't enough, the
        configured model slug must actually carry the :free suffix."""
        if not is_free_tier_provider(name):
            return False
        if name == "openrouter":
            model = getattr(config, "openrouter_model", None)
            return openrouter_model_is_free(model)
        return True

    def _detect_available(self) -> list:
        """Detect which providers have credentials configured. Under
        NEXUS_FREE_TIER_ONLY, paid/ambiguous providers are excluded even
        if a key happens to be configured for them — so a leftover paid
        key can never get silently auto-selected in free-only mode."""
        available = []
        for name, cfg in self.PROVIDER_CONFIGS.items():
            if self.free_tier_only and not self._is_effectively_free(name):
                continue
            if cfg["env_key"] is None:
                # Always available (e.g., Ollama)
                available.append(name)
            else:
                key = getattr(config, cfg["env_key"], None)
                if key:
                    available.append(name)
        return available

    def _validate_provider(self):
        if (
            self.free_tier_only
            and self.provider not in self._available_providers
            and not self._is_effectively_free(self.provider)
            and self.provider != "mock"
        ):
            # An explicitly-configured paid/ambiguous provider under
            # NEXUS_FREE_TIER_ONLY: log why it's being rejected (distinct
            # from "not configured") before falling back below, so the
            # cause is clear rather than a generic "not configured" line.
            logger.warning(
                f"NEXUS_FREE_TIER_ONLY is set — refusing paid/ambiguous provider "
                f"'{self.provider}'. Free providers available: {self._available_providers}"
            )
        if self.provider not in self._available_providers:
            logger.warning(f"Provider '{self.provider}' not configured. Available: {self._available_providers}")
            if self._available_providers:
                self.provider = self._available_providers[0]
                logger.info(f"Falling back to '{self.provider}'")
            else:
                self.provider = "mock"
                logger.info("No LLM providers configured. Using mock mode.")

    def _get_client(self):
        """Lazy-load the appropriate client based on provider."""
        if self._client is not None:
            return self._client

        if self.provider == "mock":
            self._client = MockProvider()
            return self._client

        cfg = self.PROVIDER_CONFIGS.get(self.provider, {})
        api_type = cfg.get("api_type", "openai")

        if api_type == "anthropic":
            self._client = AnthropicProvider(
                api_key=getattr(config, cfg["env_key"]),
                model=getattr(config, f"{self.provider}_model", cfg["default_model"]),
            )
        elif api_type == "azure":
            self._client = AzureProvider(
                api_key=getattr(config, cfg["env_key"]),
                endpoint=getattr(config, cfg["base_url_key"]),
                model=getattr(config, f"{self.provider}_model", cfg["default_model"]),
            )
        else:
            # OpenAI-compatible (OpenAI, OpenRouter, Ollama, Groq, DeepSeek, Omniroute, Custom)
            base_url = getattr(config, cfg["base_url_key"]) if cfg["base_url_key"] else None
            self._client = OpenAICompatibleProvider(
                api_key=getattr(config, cfg["env_key"]) if cfg["env_key"] else "ollama",
                base_url=base_url,
                model=getattr(config, f"{self.provider}_model", cfg["default_model"]),
            )
        return self._client

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Synchronous completion."""
        client = self._get_client()
        return client.complete(prompt, system=system, **kwargs)

    async def complete_async(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Async completion."""
        client = self._get_client()
        if hasattr(client, 'complete_async'):
            return await client.complete_async(prompt, system=system, **kwargs)
        return client.complete(prompt, system=system, **kwargs)

    def stream(self, prompt: str, system: Optional[str] = None, **kwargs) -> Generator[str, None, None]:
        """Stream completion tokens."""
        client = self._get_client()
        if hasattr(client, 'stream'):
            yield from client.stream(prompt, system=system, **kwargs)
        else:
            yield client.complete(prompt, system=system, **kwargs)

    def chat(self, messages: list, **kwargs) -> str:
        """Chat completion with message history."""
        client = self._get_client()
        if hasattr(client, 'chat'):
            return client.chat(messages, **kwargs)
        # Fallback: convert messages to prompt
        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
        return self.complete(prompt, **kwargs)

    def get_provider_info(self) -> dict:
        return {
            "active_provider": self.provider,
            "available_providers": self._available_providers,
            "model": getattr(config, f"{self.provider}_model", "unknown"),
            "free_tier_only": self.free_tier_only,
            "active_provider_is_free": self._is_effectively_free(self.provider) or self.provider == "mock",
        }


class MockProvider:
    """Mock provider for development/testing without API keys."""

    def complete(self, prompt: str, system: str = None, **kwargs) -> str:
        return f"[MOCK] Processed: {prompt[:100]}..."

    def stream(self, prompt: str, system: str = None, **kwargs):
        yield f"[MOCK] Processing: {prompt[:50]}..."


class OpenAICompatibleProvider:
    """Provider for any OpenAI-compatible API (OpenAI, OpenRouter, Ollama, Groq, DeepSeek, Omniroute, Custom)."""

    def __init__(self, api_key: str, base_url: Optional[str], model: str):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI
            kwargs = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = OpenAI(**kwargs)
        except ImportError:
            self._client = None
        return self._client

    def complete(self, prompt: str, system: str = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[{self.model}] Would call API with: {prompt[:100]}..."

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=kwargs.get("temperature", config.llm_temperature),
                max_tokens=kwargs.get("max_tokens", config.llm_max_tokens),
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI-compatible API error: {e}")
            return f"[ERROR] {e}"

    def stream(self, prompt: str, system: str = None, **kwargs):
        client = self._get_client()
        if client is None:
            yield f"[{self.model}] Streaming: {prompt[:50]}..."
            return

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            stream = client.chat.completions.create(
                model=self.model,
                messages=messages,
                stream=True,
                temperature=kwargs.get("temperature", config.llm_temperature),
                max_tokens=kwargs.get("max_tokens", config.llm_max_tokens),
            )
            for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            yield f"[ERROR] {e}"

    def chat(self, messages: list, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[{self.model}] Chat: {len(messages)} messages"

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=kwargs.get("temperature", config.llm_temperature),
                max_tokens=kwargs.get("max_tokens", config.llm_max_tokens),
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[ERROR] {e}"


class AnthropicProvider:
    """Provider for Anthropic Claude API."""

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self.api_key)
        except ImportError:
            self._client = None
        return self._client

    def complete(self, prompt: str, system: str = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[Claude] Would process: {prompt[:100]}..."

        try:
            message = client.messages.create(
                model=self.model,
                max_tokens=kwargs.get("max_tokens", config.llm_max_tokens),
                system=system or "",
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except Exception as e:
            return f"[ERROR] {e}"


class AzureProvider:
    """Provider for Azure OpenAI."""

    def __init__(self, api_key: str, endpoint: str, model: str):
        self.api_key = api_key
        self.endpoint = endpoint
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import AzureOpenAI
            self._client = AzureOpenAI(
                api_key=self.api_key,
                api_version="2024-02-15-preview",
                azure_endpoint=self.endpoint,
            )
        except ImportError:
            self._client = None
        return self._client

    def complete(self, prompt: str, system: str = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[Azure] Would process: {prompt[:100]}..."

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=kwargs.get("temperature", config.llm_temperature),
                max_tokens=kwargs.get("max_tokens", config.llm_max_tokens),
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[ERROR] {e}"


# Global router instance
llm_router = LLMRouter()