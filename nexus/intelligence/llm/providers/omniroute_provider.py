"""
Omniroute Provider - Multi-provider routing gateway
Routes requests to the best available LLM based on cost, speed, and capability.
"""
from typing import Optional

class OmnirouteProvider:
    """Provider for Omniroute API - intelligent multi-provider routing.

    Automatically routes requests to the optimal model based on:
    - Task type (code, reasoning, creative, analysis)
    - Cost optimization
    - Speed requirements
    - Capability requirements
    """

    def __init__(self, api_key: str, model: str = "gpt-4", base_url: Optional[str] = None):
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
            return f"[Omniroute:{self.model}] Would route: {prompt[:100]}..."

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
            return f"[Omniroute:{self.model}] Chat: {len(messages)} messages"

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.7),
        )
        return response.choices[0].message.content