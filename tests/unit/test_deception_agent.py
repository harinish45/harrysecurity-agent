"""deception_agent.py used to call the exact same 4 hardening/firewall/
endpoint/policy tools as hardening_agent.py — genuinely identical, doing
zero deception-specific work despite the name (found during this session's
audit). It now calls a real canary-token/decoy-credential generator
(blue_team.canary_token_deployment) instead — these tests confirm both the
new tool and the rewired agent."""
import pytest

from nexus.agents.defensive.deception_agent import DeceptionAgent
from nexus.tools.blue_team.canary_token_deployment import run as canary_run


def test_canary_token_deployment_generates_target_specific_decoys():
    result = canary_run("app.example.com")
    assert result["status"] == "completed"
    assert len(result["findings"]) == 4
    # Every generated decoy is a plain string finding embedding real,
    # randomized content — not a fixed canned string.
    assert all(isinstance(f, str) for f in result["findings"])
    assert any("AWS credential" in f for f in result["findings"])
    assert any("admin-panel URL" in f for f in result["findings"])
    assert any("DNS canary" in f for f in result["findings"])


def test_canary_token_deployment_is_randomized_per_call():
    first = canary_run("app.example.com")
    second = canary_run("app.example.com")
    assert first["findings"] != second["findings"]


@pytest.mark.asyncio
async def test_deception_agent_calls_canary_tool_not_hardening_duplicate(monkeypatch):
    calls = []

    def fake_run(name, **kwargs):
        calls.append(name)
        return {"status": "completed", "findings": [f"finding from {name}"]}

    monkeypatch.setattr("nexus.agents.defensive.deception_agent.tool_registry.run", fake_run)

    result = await DeceptionAgent().run("deploy deception", target="127.0.0.1")

    assert result["status"] == "completed"
    assert "blue_team.canary_token_deployment" in calls
    # The old bug: this agent called the exact same tools as
    # hardening_agent.py (blue_team.hardening, blue_team.firewall_management)
    # instead of anything deception-specific.
    assert "blue_team.hardening" not in calls
    assert "blue_team.firewall_management" not in calls


@pytest.mark.asyncio
async def test_deception_agent_fails_cleanly_with_no_target():
    result = await DeceptionAgent().run("deploy deception", target="")
    assert result["status"] == "failed"
    assert result["error"]
