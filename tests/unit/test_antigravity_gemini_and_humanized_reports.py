"""Tests for Google Antigravity, Google Gemini, Local AI Models (Ollama, LM Studio),
and authentic humanized report generation with zero fake/mock data.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from nexus.foundation.config import config
from nexus.foundation.free_tier import is_free_tier_provider
from nexus.intelligence.llm.router import LLMRouter, OpenAICompatibleProvider
from nexus.reporting.generator import ReportGenerator
from nexus.agents.orchestrator.report_tone_agent import ReportToneAgent


def test_free_tier_includes_antigravity_and_lmstudio_and_gemini():
    assert is_free_tier_provider("antigravity") is True
    assert is_free_tier_provider("lmstudio") is True
    assert is_free_tier_provider("gemini") is True


def test_antigravity_provider_dispatch(monkeypatch):
    monkeypatch.setattr(config, "antigravity_api_key", "ag-test-key")
    monkeypatch.setattr(config, "antigravity_base_url", "http://127.0.0.1:20128/v1")
    monkeypatch.setattr(config, "antigravity_model", "gemini-2.5-pro")

    router = LLMRouter(provider="antigravity")
    client = router._get_client()

    assert isinstance(client, OpenAICompatibleProvider)
    assert client.api_key == "ag-test-key"
    assert client.base_url == "http://127.0.0.1:20128/v1"
    assert client.model == "gemini-2.5-pro"


def test_gemini_provider_dispatch(monkeypatch):
    monkeypatch.setattr(config, "gemini_api_key", "gemini-fake-key")
    monkeypatch.setattr(config, "gemini_model", "gemini-2.5-flash")
    monkeypatch.setattr(config, "gemini_base_url", "https://generativelanguage.googleapis.com/v1beta/openai/")

    router = LLMRouter(provider="gemini")
    client = router._get_client()

    assert isinstance(client, OpenAICompatibleProvider)
    assert client.api_key == "gemini-fake-key"
    assert client.base_url == "https://generativelanguage.googleapis.com/v1beta/openai/"
    assert client.model == "gemini-2.5-flash"


def test_lmstudio_provider_dispatch(monkeypatch):
    monkeypatch.setattr(config, "lmstudio_api_key", "lm-studio-local")
    monkeypatch.setattr(config, "lmstudio_model", "qwen2.5-coder")
    monkeypatch.setattr(config, "lmstudio_base_url", "http://localhost:1234/v1")

    router = LLMRouter(provider="lmstudio")
    client = router._get_client()

    assert isinstance(client, OpenAICompatibleProvider)
    assert client.api_key == "lm-studio-local"
    assert client.base_url == "http://localhost:1234/v1"
    assert client.model == "qwen2.5-coder"


@pytest.mark.asyncio
async def test_simultaneous_parallel_completions(monkeypatch):
    """Verify that multiple agents making concurrent LLM requests to local or cloud
    providers execute simultaneously without state pollution or race conditions."""
    fake_client = MagicMock()
    call_counts = {"count": 0}

    def fake_create(**kwargs):
        call_counts["count"] += 1
        msg = MagicMock(content=f"Response to: {kwargs['messages'][-1]['content']}")
        resp = MagicMock()
        resp.choices = [MagicMock(message=msg)]
        return resp

    fake_client.chat.completions.create.side_effect = fake_create

    provider = OpenAICompatibleProvider(api_key="local-key", base_url="http://127.0.0.1:20128/v1", model="gemini-2.5-pro")
    provider._client = fake_client

    async def _agent_query(agent_id: int) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, provider.complete, f"prompt-{agent_id}")

    # Launch 10 simultaneous agent requests
    tasks = [_agent_query(i) for i in range(10)]
    results = await asyncio.gather(*tasks)

    assert len(results) == 10
    assert all("Response to: prompt-" in r for r in results)
    assert call_counts["count"] == 10


def test_report_generator_contains_no_mock_or_tbd_placeholders():
    generator = ReportGenerator()
    findings = [
        {
            "id": "F-001",
            "title": "[MOCK] Unauthenticated Remote Code Execution",
            "severity": "critical",
            "evidence": "[MOCK] Executed id and received uid=0(root)",
            "remediation": "[MOCK] Disable vulnerable endpoint and sanitize input",
            "affected_asset": "192.168.1.100:8080",
            "tool": "exploit.rce_probe",
        },
        {
            "id": "F-002",
            "title": "SQL Injection in Search Form",
            "severity": "high",
            "evidence": "Extracted database version via UNION SELECT",
            "remediation": "Use prepared statements",
            "affected_asset": "192.168.1.100:443",
            "tool": "webapp.sqli_scan",
        },
    ]

    report = generator.generate(findings, target="192.168.1.100", mission_id="mission-audit")

    # Authenticity check
    auth = ReportGenerator.validate_authenticity(report)
    assert auth["authentic"] is True
    assert auth["violations"] == []

    # Verify no mock markers survived
    assert "[MOCK]" not in report
    assert "TBD" not in report

    # Verify professional executive content
    assert "Security Assessment Report" in report
    assert "Executive summary" in report
    assert "Remediation priorities" in report
    assert "Security Engineering" in report
    assert "Within 48h" in report


@pytest.mark.asyncio
async def test_report_tone_agent_humanized_and_authentic_output():
    agent = ReportToneAgent()
    findings = [
        {
            "id": "F-10",
            "title": "SQL Injection",
            "severity": "critical",
            "evidence": "' OR '1'='1 returned full user table",
            "remediation": "Implement parameterized queries",
            "tool": "webapp.sqli_scan",
            "affected_asset": "https://api.example.com",
            "business_impact": "Full database breach",
        }
    ]

    for mode in ("pentest", "redteam", "bounty", "compliance", "ctf"):
        res = await agent.run("render", target="https://api.example.com", mode=mode, findings=findings)
        report_text = res["metadata"]["rendered_report"]

        # Ensure no mock or placeholder text
        assert "[MOCK]" not in report_text
        assert "unknown tool" not in report_text
        assert "TBD" not in report_text
        assert "Impact not yet annotated" not in report_text

        # Ensure humanized narrative
        assert "SQL Injection" in report_text
        assert "webapp.sqli_scan" in report_text
        assert "Severity Distribution:" in report_text or "## Steps to Reproduce" in report_text or "## Challenge" in report_text
