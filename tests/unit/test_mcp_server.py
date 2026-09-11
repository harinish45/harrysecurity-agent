"""`nexus mcp` used to be a complete stub — it printed "MCP Server
implementation coming in Phase 2." and did nothing real. This tests the
actual MCP server built to replace it: real protocol-level round-trips
via the official `mcp` SDK's in-process `Client`, and confirmation that
an MCP client is not a new guardrail-bypass path into the platform.
"""
import pytest

from nexus.foundation.config import config
from nexus.mcp.server import create_server

pytestmark = pytest.mark.asyncio


def _payload(call_tool_result):
    """Return a tool call's real structured result. Per the MCP spec's
    structured-tool-output feature, the SDK returns a dict-shaped tool
    return value as-is in `structured_content`, and wraps a list-shaped
    one as `{"result": [...]}` (a bare JSON array isn't a valid top-level
    object everywhere); `content` carries a human-readable text rendering
    instead of the typed value, which is not what these tests need."""
    structured = call_tool_result.structured_content
    assert structured is not None, "tool call returned no structured content"
    if set(structured.keys()) == {"result"}:
        return structured["result"]
    return structured


async def test_real_tools_list_matches_registered_tools():
    """A real MCP `tools/list` round-trip — not a mock — must return all
    7 registered tools with real (non-empty) JSON schemas derived from the
    actual function signatures."""
    from mcp.client import Client

    server = create_server()
    async with Client(server) as client:
        listed = await client.list_tools()

    names = {t.name for t in listed.tools}
    assert names == {
        "list_domains", "list_tools", "list_agents",
        "run_tool", "run_mission", "get_mission_status", "get_report",
    }
    run_tool_schema = next(t for t in listed.tools if t.name == "run_tool").input_schema
    assert set(run_tool_schema["required"]) == {"tool_name", "target"}


async def test_list_domains_returns_real_registry_data():
    from mcp.client import Client

    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool("list_domains", {})

    domains = _payload(result)
    assert isinstance(domains, list)
    assert "network" in domains
    assert "webapp" in domains


async def test_list_tools_domain_filter_is_real_not_mocked():
    from mcp.client import Client

    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool("list_tools", {"domain": "network"})

    tools = _payload(result)
    assert tools, "expected at least one real network tool"
    assert all(t["domain"] == "network" for t in tools)
    assert any(t["name"] == "network.port_scan" for t in tools)


async def test_run_tool_out_of_scope_target_is_rejected_not_bypassed(monkeypatch):
    """The single most important guardrail-integrity test for this new
    entry point: an MCP client must not be able to reach an out-of-scope
    target that a CLI-invoked scan would refuse."""
    from mcp.client import Client

    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool(
            "run_tool", {"tool_name": "network.port_scan", "target": "totally-out-of-scope.invalid"}
        )

    payload = _payload(result)
    assert payload["status"] == "failed"
    assert "Guardrail blocked" in payload["error"]


async def test_run_tool_missing_legal_ack_is_rejected(monkeypatch):
    """Even an in-scope target must still pass LegalGuard — confirms the
    MCP entrypoint applies the FULL chain, not just ScopeGuard."""
    from mcp.client import Client

    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "")
    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool("run_tool", {"tool_name": "network.port_scan", "target": "127.0.0.1"})

    payload = _payload(result)
    assert payload["status"] == "failed"
    assert "Guardrail blocked" in payload["error"]


async def test_run_tool_authorized_in_scope_call_succeeds_end_to_end(monkeypatch):
    """The happy path: a properly authorized, in-scope call through the
    MCP entrypoint gets a real tool_result back, same shape as a direct
    tool_registry.run() call."""
    from mcp.client import Client

    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool("run_tool", {"tool_name": "network.port_scan", "target": "127.0.0.1"})

    payload = _payload(result)
    assert payload["status"] in ("completed", "no_findings")


async def test_run_tool_params_target_collision_is_a_clean_error_not_a_crash(monkeypatch):
    """`run_tool(tool_name, target, params)` used to expand `params` straight
    into `tool_registry.run(tool_name, target, **params)`. An MCP client's
    `params` dict is arbitrary, caller-controlled input (unlike every other
    tool_registry.run() call site in this codebase, which passes a fixed,
    hardcoded kwarg set) — if it happens to contain a `target` key, that
    collides with the `target` keyword this call already supplies, and
    Python raises "got multiple values for argument 'target'" as an
    unhandled TypeError at the call itself, before any guardrail runs.
    Confirms this now degrades to a clean failed tool_result instead."""
    from mcp.client import Client

    monkeypatch.setattr(config, "nexus_allowed_targets", "127.0.0.1,localhost")
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool(
            "run_tool",
            {
                "tool_name": "network.port_scan",
                "target": "127.0.0.1",
                "params": {"target": "evil-override", "extra": "x"},
            },
        )

    payload = _payload(result)
    assert payload["status"] == "failed"
    assert "target" in payload["error"].lower()
    assert payload["tool"] == "network.port_scan"
    assert "findings" in payload


async def test_get_mission_status_for_unknown_mission_is_honest():
    from mcp.client import Client

    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool("get_mission_status", {"mission_id": "definitely-nonexistent-mission-id"})

    payload = _payload(result)
    assert payload["state"] == "unknown"
    assert payload["report_available"] is False


async def test_get_report_for_missing_mission_returns_error_not_crash():
    from mcp.client import Client

    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool("get_report", {"mission_id": "definitely-nonexistent-mission-id"})

    payload = _payload(result)
    assert "error" in payload


async def test_list_agents_tier_filter_returns_real_registry_entries():
    from mcp.client import Client

    server = create_server()
    async with Client(server) as client:
        result = await client.call_tool("list_agents", {"tier": "offensive"})

    agents = _payload(result)
    assert agents, "expected at least one real offensive-tier agent"
    assert all(a["tier"] == "offensive" for a in agents)
    assert all(a["class_path"] for a in agents)
