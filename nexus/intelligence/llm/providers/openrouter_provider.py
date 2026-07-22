"""
OpenRouter Provider - Gateway to 200+ models (GPT-4, Claude, Gemini, Llama, Mistral, etc.)
"""
from typing import Optional

class OpenRouterProvider:
    """Provider for OpenRouter API.

    Provides access to 200+ models through a single API.
    Supports: openai/gpt-4-turbo, anthropic/claude-3-opus, meta-llama/llama-3-70b, etc.
    """

    def __init__(self, api_key: str, model: str = "openai/gpt-4-turbo", base_url: str = "https://openrouter.ai/api/v1"):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                default_headers={
                    "HTTP-Referer": "https://github.com/nexus-strike",
                    "X-Title": "NEXUS-STRIKE",
                }
            )
        except ImportError:
            self._client = None
        return self._client

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[OpenRouter:{self.model}] Would call with: {prompt[:100]}..."

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens", 4096),
        )
        return response.choices[0].message.content

    def chat(self, messages: list, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[OpenRouter:{self.model}] Chat: {len(messages)} messages"

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens", 4096),
        )
        return response.choices[0].message.content