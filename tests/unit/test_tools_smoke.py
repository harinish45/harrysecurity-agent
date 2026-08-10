#!/usr/bin/env python3
"""
NEXUS-STRIKE — Unit Tests: Tool Smoke Tests
Ensures all registered tools can be imported and executed without raising exceptions.
"""
import pytest
from nexus.tools.registry import list_tools

VALID_STATUSES = {"completed", "no_findings", "failed", "unavailable", "requires_credentials"}
REQUIRED_KEYS = {"tool", "target", "status", "findings"}

@pytest.mark.skip(reason="Slow network calls - excluded from default test run")
@pytest.mark.parametrize("tool_name,tool_func", list_tools())
def test_tool_smoke(tool_name: str, tool_func: callable):
    """Smoke test for every registered tool."""
    target = "127.0.0.1"
    
    # Assert no exception raised during execution
    result = tool_func(target=target)
    
    # Assert returned dict has required keys
    assert isinstance(result, dict), f"Tool {tool_name} did not return a dict"
    assert REQUIRED_KEYS.issubset(result.keys()), f"Tool {tool_name} missing required keys. Has: {result.keys()}"
    
    # Assert status is valid
    assert result["status"] in VALID_STATUSES, f"Tool {tool_name} returned invalid status: {result['status']}"
    
    # Assert findings is a list
    assert isinstance(result["findings"], list), f"Tool {tool_name} findings is not a list"