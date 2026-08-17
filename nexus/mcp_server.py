"""Read-only Model Context Protocol control plane for NEXUS-STRIKE.

The MCP surface intentionally exposes inventory, provider status and preflight
information only. Security-tool execution remains behind the normal mission
engine and guardrail pipeline; MCP cannot bypass authorization or sandboxing.
"""

from __future__ import annotations

import importlib.util
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.agents.agent_registry import get_agent_count, list_agents
from nexus.foundation.config import config
from nexus.intelligence.llm.router import LLMRouter
from nexus.tools.registry import tool_registry


mcp = FastMCP(
    "NEXUS-STRIKE",
    instructions=(
        "NEXUS-STRIKE security assessment control plane. This server is read-only: "
        "use it to inspect tool/agent inventory and readiness. Do not treat inventory "
        "as authorization to execute a security test."
    ),
)


def _preflight() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for dependency in ("httpx", "fastapi", "pydantic", "yaml"):
        ready = importlib.util.find_spec(dependency) is not None
        checks.append({"name": f"python:{dependency}", "ready": ready})

    checks.extend(
        [
            {
                "name": "written_authorization",
                "ready": config.nexus_legal_ack == "I_HAVE_WRITTEN_AUTHORIZATION",
            },
            {
                "name": "target_allow_list",
                "ready": bool(str(config.nexus_allowed_targets).strip()),
            },
        ]
    )
    provider = LLMRouter()
    checks.append({"name": "llm_provider", "ready": provider.provider != "mock"})
    return {
        "ready": all(item["ready"] for item in checks),
        "checks": checks,
        "allowed_targets_configured": bool(str(config.nexus_allowed_targets).strip()),
    }


@mcp.resource("nexus://status")
def status() -> str:
    """Return a compact, non-sensitive platform status document."""
    provider = LLMRouter()
    return (
        "NEXUS-STRIKE status\n"
        f"tools={tool_registry.count}\n"
        f"agents={get_agent_count()}\n"
        f"llm_provider={provider.provider}\n"
        f"preflight_ready={_preflight()['ready']}\n"
        "execution_via_mcp=disabled"
    )


@mcp.resource("nexus://tools")
def tools_resource() -> str:
    """Return registered security-tool names grouped by their registry keys."""
    tools = tool_registry.list_tools()
    lines = ["NEXUS-STRIKE tool inventory", f"count={len(tools)}"]
    lines.extend(f"{name}: {type(tool).__name__}" for name, tool in sorted(tools.items()))
    return "\n".join(lines)


@mcp.tool()
def list_security_tools(domain: str | None = None) -> dict[str, Any]:
    """List registered tools without executing any tool."""
    tools = tool_registry.list_tools()
    if domain:
        tools = {name: tool for name, tool in tools.items() if name.startswith(domain)}
    return {
        "count": len(tools),
        "tools": [
            {"name": name, "type": type(tool).__name__}
            for name, tool in sorted(tools.items())
        ],
    }


@mcp.tool()
def platform_status() -> dict[str, Any]:
    """Return non-secret runtime, provider and guardrail readiness information."""
    provider = LLMRouter()
    return {
        "tool_count": tool_registry.count,
        "agent_count": get_agent_count(),
        "provider": provider.provider,
        "preflight": _preflight(),
        "mcp_execution": "disabled",
    }


@mcp.tool()
def list_agents_readonly() -> list[dict[str, Any]]:
    """List registered agents without starting an agent or mission."""
    agents = list_agents()
    return [
        {"name": getattr(agent, "name", str(agent)), "type": type(agent).__name__}
        for agent in agents
    ]


def run() -> None:
    """Start the MCP server over stdio for desktop/IDE MCP clients."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
