from pathlib import Path


def test_llm_control_center_contains_provider_matrix_and_safe_routing_controls():
    page = Path("web/static/llm-providers.html").read_text(encoding="utf-8")

    for provider in ("Ollama", "OpenAI", "Anthropic", "OpenRouter", "Azure OpenAI", "Groq", "DeepSeek"):
        assert provider in page
    for control in ("preferred", "fallbacks", "modelClass", "costTier", "requireLocal", "requireTools"):
        assert control in page

    # Secrets must remain server-side; the control center stores only safe browser policy metadata.
    assert "type=\"password\"" not in page.lower()
    assert "api_key" not in page.lower()
    assert "secret=" not in page.lower()
    assert "browser-local profile" in page
