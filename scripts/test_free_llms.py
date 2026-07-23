#!/usr/bin/env python3
"""
NEXUS-STRIKE Free LLM Provider Test
Tests all configured free providers and reports which ones are working.

Usage:
    python scripts/test_free_llms.py
"""

import os
import sys
import time

# --- UTF-8 safety for Windows ---
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env already loaded by shell or not needed


TIMEOUT_SECONDS = 30
TEST_PROMPT = "Reply with exactly one word: ready"


def _build_providers() -> list[dict]:
    """Build provider list from environment variables."""
    providers = []

    def add(name: str, base_url: str, api_key: str, model: str) -> None:
        """Register a provider if base_url and model are both set."""
        if not base_url or not model:
            return
        url = base_url.rstrip("/")
        if not url.endswith("/chat/completions"):
            url = f"{url}/chat/completions"
        providers.append({"name": name, "url": url, "api_key": api_key or "none", "model": model})

    # 1. Local Ollama
    add(
        name="ollama",
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key="ollama",
        model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder:latest"),
    )

    # 2. NVIDIA NIM
    add(
        name="nvidia",
        base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
        api_key=os.getenv("NVIDIA_API_KEY", ""),
        model=os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
    )

    # 3. OpenRouter free
    add(
        name="openrouter",
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        api_key=os.getenv("OPENROUTER_API_KEY", ""),
        model=os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free"),
    )

    # 4. Groq (free tier)
    add(
        name="groq",
        base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
        api_key=os.getenv("GROQ_API_KEY", ""),
        model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
    )

    # 5. Omniroute
    add(
        name="omniroute",
        base_url=os.getenv("OMNIROUTE_BASE_URL", ""),
        api_key=os.getenv("OMNIROUTE_API_KEY", ""),
        model=os.getenv("OMNIROUTE_MODEL", ""),
    )

    # 6. Custom / LM Studio / Antigravity
    add(
        name="custom",
        base_url=os.getenv("CUSTOM_BASE_URL", ""),
        api_key=os.getenv("CUSTOM_API_KEY", "none"),
        model=os.getenv("CUSTOM_MODEL", ""),
    )

    return providers


def _test_provider(provider: dict) -> tuple[bool, str]:
    """
    Send a minimal chat completion request.
    Returns (success, detail_message).
    """
    name = provider["name"]
    url = provider["url"]
    api_key = provider["api_key"]
    model = provider["model"]

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": TEST_PROMPT}],
        "max_tokens": 16,
        "temperature": 0,
    }

    start = time.time()
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT_SECONDS)
        elapsed = round(time.time() - start, 2)

        if resp.status_code == 200:
            data = resp.json()
            content = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()[:80]
            )
            return True, f"{elapsed}s — reply: '{content}'"
        else:
            return False, f"HTTP {resp.status_code} — {resp.text[:200]}"

    except requests.exceptions.ConnectionError as exc:
        return False, f"Connection refused (is the server running?): {exc}"
    except requests.exceptions.Timeout:
        return False, f"Timed out after {TIMEOUT_SECONDS}s"
    except Exception as exc:
        return False, str(exc)[:200]


def _print_separator(char: str = "=", width: int = 72) -> None:
    print(char * width)


def main() -> None:
    _print_separator()
    print("  NEXUS-STRIKE — Free LLM Provider Check")
    _print_separator()

    providers = _build_providers()
    if not providers:
        print("No providers configured. Edit .env and add at least OLLAMA_BASE_URL.")
        sys.exit(1)

    passed: list[str] = []
    failed: list[str] = []

    for p in providers:
        print(f"\n  Testing : {p['name']}")
        print(f"  Model   : {p['model']}")
        print(f"  URL     : {p['url']}")

        ok, detail = _test_provider(p)
        status = "PASS" if ok else "FAIL"
        print(f"  Result  : [{status}] {detail}")

        if ok:
            passed.append(p["name"])
        else:
            failed.append(p["name"])

    _print_separator()
    print("  SUMMARY")
    _print_separator()
    print(f"  Passed : {', '.join(passed) if passed else 'none'}")
    print(f"  Failed : {', '.join(failed) if failed else 'none'}")

    if passed:
        best = passed[0]
        print(f"\n  Recommended LLM_PROVIDER: {best}")
        print(f"  Add this to .env:  LLM_PROVIDER={best}")
    else:
        print("\n  No providers passed. Start Ollama or add an API key.")
        print("  To start Ollama: ollama serve")
        print("  To pull a model: ollama pull qwen2.5-coder:latest")

    _print_separator()


if __name__ == "__main__":
    main()
