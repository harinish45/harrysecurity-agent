from nexus.mcp_server import list_agents_readonly, list_security_tools, platform_status, status


def test_mcp_status_is_read_only():
    value = status()
    assert "execution_via_mcp=disabled" in value


def test_mcp_tool_inventory_does_not_execute_tools():
    result = list_security_tools()
    assert isinstance(result["tools"], list)
    assert result["count"] == len(result["tools"])


def test_mcp_platform_status_exposes_preflight_only():
    result = platform_status()
    assert result["mcp_execution"] == "disabled"
    assert "preflight" in result
    assert "allowed_targets_configured" in result["preflight"]


def test_mcp_agent_inventory_is_read_only():
    result = list_agents_readonly()
    assert result
    assert all(set(item) == {"name", "available"} for item in result)
