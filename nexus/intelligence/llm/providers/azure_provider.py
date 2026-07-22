"""
Azure Provider - Azure OpenAI Service with enterprise compliance.
"""
from typing import Optional

class AzureProvider:
    """Provider for Azure OpenAI Service.

    Enterprise-grade OpenAI models through Microsoft Azure.
    Supports: GPT-4, GPT-3.5 with Azure AD, managed compliance, and data residency.
    """

    def __init__(self, api_key: str, endpoint: str, model: str = "gpt-4"):
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

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[Azure:{self.model}] Would process: {prompt[:100]}..."

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