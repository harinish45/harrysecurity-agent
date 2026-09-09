"""
Groq Provider - Ultra-fast inference with LPU technology.
"""
from typing import Optional

class GroqProvider:
    """Provider for Groq API - fastest LLM inference available.

    Uses LPU inference engine for extremely fast responses.
    Mixtral/Llama-3.1/Llama-3.3 model IDs have since been decommissioned by
    Groq (confirmed live: 404 model_not_found as of 2026-09) — current
    default is openai/gpt-oss-20b, verified reachable against a real key.
    """

    def __init__(self, api_key: str, model: str = "openai/gpt-oss-20b", base_url: str = "https://api.groq.com/openai/v1"):
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
            return f"[Groq:{self.model}] Would call with: {prompt[:100]}..."

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens", 32768),
        )
        return response.choices[0].message.content