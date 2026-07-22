"""
Custom Provider - Connect to any OpenAI-compatible or custom API endpoint.
"""
from typing import Optional

class CustomProvider:
    """Provider for custom/self-hosted API endpoints.

    Connects to any OpenAI-compatible API endpoint or custom implementation.
    Useful for: self-hosted models, enterprise gateways, proxy services, custom backends.
    """

    def __init__(self, api_key: str, model: str = "custom-model", base_url: Optional[str] = None, api_type: str = "openai"):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.api_type = api_type  # openai, anthropic, or custom
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client

        if self.api_type == "openai" and self.base_url:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.api_key or "custom-key",
                    base_url=self.base_url,
                )
            except ImportError:
                self._client = None
        elif self.api_type == "anthropic":
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None
        return self._client

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[Custom:{self.model}] Would process: {prompt[:100]}..."

        if self.api_type == "anthropic":
            message = client.messages.create(
                model=self.model,
                max_tokens=kwargs.get("max_tokens", 4096),
                system=system or "",
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        else:
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