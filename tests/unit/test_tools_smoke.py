#!/usr/bin/env python3
"""
NEXUS-STRIKE — Unit Tests: Tool Smoke Tests
Ensures all registered tools can be imported and executed without raising exceptions.

Every tool call here targets 127.0.0.1 only — never an external host — so this
is genuinely safe to run for real; it's marked `slow` (not `skip`) purely
because running all ~290 tools' real socket-connect/timeout paths against
localhost takes longer than the rest of the unit suite combined, not because
it's unsafe or would touch anything outside this machine. Run explicitly with
`pytest tests/unit/test_tools_smoke.py -m slow` (or without the default
`-k "not slow"` filter).
"""
import pytest
from nexus.foundation.schema import ALL_STATUSES
from nexus.tools.registry import list_tools

REQUIRED_KEYS = {"tool", "target", "status", "findings"}

@pytest.mark.slow
@pytest.mark.parametrize("tool_name,tool_func", list_tools())
def test_tool_smoke(tool_name: str, tool_func: callable):
    """Smoke test for every registered tool."""
    target = "127.0.0.1"

    # Assert no exception raised during execution
    result = tool_func(target=target)

    # Assert returned dict has required keys
    assert isinstance(result, dict), f"Tool {tool_name} did not return a dict"
    assert REQUIRED_KEYS.issubset(result.keys()), f"Tool {tool_name} missing required keys. Has: {result.keys()}"

    # Assert status is valid — imports the real, current status set from
    # schema.py instead of a hand-duplicated literal, so this can't silently
    # go stale again as new honest-degrade statuses (requires_hardware,
    # requires_file, requires_sandbox, out_of_scope, not_implemented) are added.
    assert result["status"] in ALL_STATUSES, f"Tool {tool_name} returned invalid status: {result['status']}"

    # Assert findings is a list
    assert isinstance(result["findings"], list), f"Tool {tool_name} findings is not a list"


def test_all_registered_tools_schema_contract():
    """Fast parallel verification that all registered tools across all domains
    execute safely against 127.0.0.1 and strictly satisfy the schema contract."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tools = list_tools()
    assert len(tools) >= 266, f"Expected at least 266 registered tools, found {len(tools)}"

    def _verify(item):
        name, fn = item
        res = fn(target="127.0.0.1")
        assert isinstance(res, dict), f"Tool {name} did not return a dict"
        assert REQUIRED_KEYS.issubset(res.keys()), f"Tool {name} missing required keys. Has: {res.keys()}"
        assert res["status"] in ALL_STATUSES, f"Tool {name} returned invalid status: {res['status']}"
        assert isinstance(res["findings"], list), f"Tool {name} findings is not a list"
        return name

    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(_verify, t) for t in tools]
        results = [f.result() for f in as_completed(futures)]

    assert len(results) == len(tools)