"""
Ollama Provider - Local LLMs (Llama 3, Mistral, CodeLlama, Phi, etc.)
Runs fully offline with no API key required.
"""
from typing import Optional

class OllamaProvider:
    """Provider for Ollama local LLMs.

    Runs models locally on your machine. No API key required.
    Supports: llama3.2, llama3.1, mistral, codellama, phi, neural-chat, and more.
    """

    def __init__(self, model: str = "llama3.2", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI
            self._client = OpenAI(
                api_key="ollama",  # Ollama requires a non-empty string
                base_url=f"{self.base_url}/v1",
            )
        except ImportError:
            self._client = None
        return self._client

    def complete(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        client = self._get_client()
        if client is None:
            return f"[Ollama:{self.model}] Would call with: {prompt[:100]}..."

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens", 4096),
            stream=False,
        )
        return response.choices[0].message.content

    def stream(self, prompt: str, system: Optional[str] = None, **kwargs):
        client = self._get_client()
        if client is None:
            yield f"[Ollama:{self.model}] Streaming..."
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