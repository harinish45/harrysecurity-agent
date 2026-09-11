"""tool_registry.run() must route through the guardrailed ToolExecutor, not
call the raw tool function directly — this is what closes the gap where
every one of the 60 agents used to call tool_registry.get(name)(...) and
skip InputGuard/ScopeGuard/LegalGuard/RateGuard/AuditGuard entirely."""
import pytest

from nexus.foundation.schema import STATUS_COMPLETED, tool_result
from nexus.tools.registry import tool_registry


def _dummy_tool(target: str, **kwargs) -> dict:
    return tool_result("dummy.tool", target, status=STATUS_COMPLETED, summary="ok")


@pytest.fixture
def registered_dummy(monkeypatch):
    """Register a throwaway tool on the real (global) registry for the
    duration of one test — ToolExecutor always resolves tools via the global
    singleton, so this must live there, not on a private instance. monkeypatch
    reverts the dict mutation automatically at teardown."""
    monkeypatch.setitem(tool_registry._tools, "dummy.tool", _dummy_tool)
    monkeypatch.setitem(
        tool_registry._metadata, "dummy.tool", {"name": "dummy.tool", "domain": "dummy", "status": "active"}
    )
    return "dummy.tool"


def test_get_returns_the_raw_undecorated_function(registered_dummy):
    fn = tool_registry.get(registered_dummy)
    raw = fn(target="127.0.0.1")
    # The raw function's own result has no execution_ms — that only gets
    # added by ToolExecutor.run(), proving get() does not go through it.
    assert "execution_ms" not in raw.get("metadata", {})


def test_run_goes_through_tool_executor(registered_dummy, monkeypatch):
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    result = tool_registry.run(registered_dummy, target="127.0.0.1")

    assert result["status"] == STATUS_COMPLETED
    # execution_ms is injected exclusively by ToolExecutor.run() — its
    # presence proves the call was guardrailed, not a raw invocation.
    assert "execution_ms" in result["metadata"]


def test_run_blocks_a_guardrail_violation(registered_dummy):
    # A null-byte target trips InputGuard before the tool ever runs.
    result = tool_registry.run(registered_dummy, target="127.0.0.1\x00")

    assert result["status"] == "failed"
    assert "guardrail" in result["error"].lower() or "blocked" in result["error"].lower()
