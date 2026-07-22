"""
DeepSeek Provider - Advanced reasoning models with competitive pricing.
"""
from typing import Optional

class DeepSeekProvider:
    """Provider for DeepSeek API.

    Known for strong reasoning capabilities and competitive pricing.
    Supports: deepseek-chat, deepseek-coder, and more.
    """

    def __init__(self, api_key: str, model: str = "deepseek-chat", base_url: str = "https://api.deepseek.com/v1"):
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
            )
        except ImportError:
            self._client = None
        return self._client

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[DeepSeek:{self.model}] Would call with: {prompt[:100]}..."

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