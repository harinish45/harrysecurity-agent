"""debugger_agent used to return the same 4 generic suggested_fixes
unconditionally, regardless of what was actually investigated — this makes
the suggestions depend on which tools actually ran and what was found."""
import pytest

from nexus.agents.support.debugger_agent import DebuggerAgent


@pytest.mark.asyncio
async def test_suggestions_differ_between_memory_and_generic_tasks(monkeypatch):
    def fake_run(name, **kwargs):
        return {"status": "completed", "findings": []}

    monkeypatch.setattr("nexus.agents.support.debugger_agent.tool_registry.run", fake_run)

    agent = DebuggerAgent()
    memory_result = await agent.run("investigate a memory leak", target="127.0.0.1")
    generic_result = await agent.run("unrelated task with no matching keywords", target="127.0.0.1")

    assert memory_result["metadata"]["suggested_fixes"] != generic_result["metadata"]["suggested_fixes"]


@pytest.mark.asyncio
async def test_no_matching_tool_still_returns_actionable_guidance(monkeypatch):
    agent = DebuggerAgent()
    result = await agent.run("some task with no matching keywords at all", target="127.0.0.1")
    assert result["metadata"]["suggested_fixes"]
