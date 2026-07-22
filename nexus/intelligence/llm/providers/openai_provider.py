"""
OpenAI Provider - GPT-4, GPT-3.5, and all OpenAI models.
"""
from typing import Optional

class OpenAIProvider:
    """Provider for OpenAI API.

    Supports: gpt-4-turbo, gpt-4, gpt-3.5-turbo, and all OpenAI models.
    Can be configured with custom base_url for proxy/compatible setups.
    """

    def __init__(self, api_key: str, model: str = "gpt-4-turbo", base_url: Optional[str] = None):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
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

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[OpenAI:{self.model}] Would call with: {prompt[:100]}..."

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

    def stream(self, prompt: str, system: Optional[str] = None, **kwargs):
        client = self._get_client()
        if client is None:
            yield f"[OpenAI:{self.model}] Streaming..."
            return

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        stream = client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=True,
            temperature=kwargs.get("temperature", 0.7),
        )
        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def chat(self, messages: list, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[OpenAI:{self.model}] Chat: {len(messages)} messages"

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens", 4096),
        )
        return response.choices[0].message.content