"""
Anthropic Provider - Claude 3 models (Opus, Sonnet, Haiku)
"""
from typing import Optional

class AnthropicProvider:
    """Provider for Anthropic Claude API.

    Supports: claude-3-opus, claude-3-sonnet, claude-3-haiku
    Known for safety, reasoning, and long context handling.
    """

    def __init__(self, api_key: str, model: str = "claude-3-opus-20240229"):
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

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[Claude:{self.model}] Would process: {prompt[:100]}..."

        message = client.messages.create(
            model=self.model,
            max_tokens=kwargs.get("max_tokens", 4096),
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    def chat(self, messages: list, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[Claude:{self.model}] Chat: {len(messages)} messages"

        message = client.messages.create(
            model=self.model,
            max_tokens=kwargs.get("max_tokens", 4096),
            messages=messages,
        )
        return message.content[0].text