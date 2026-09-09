"""The real NEXUS-STRIKE MCP server.

Every operation exposed here reuses the platform's existing, already-
guardrailed entrypoints — it does not open a new, less-safe path into the
platform:

- `run_tool` calls `tool_registry.run()`, which internally builds a
  `ToolExecutor` and runs the full guardrail chain (Input/Scope/Legal/
  Escalation/Rate/Audit/Output) exactly like a CLI-invoked scan does.
- `run_mission` calls the real `OrchestrationEngine.run_mission()` — the
  same coroutine `nexus run`/`nexus pentest`/etc. await — so mission-level
  guardrails (`ScopeGuard`/`LegalGuard`/`EscalationGuard` at mission start)
  apply identically.

An MCP client is a new caller of this platform, not a trusted internal
component; it must not become a guardrail bypass.
"""
from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from nexus import __version__ as _nexus_version
from nexus.foundation.paths import safe_join, safe_slug

_ENGAGEMENTS_ROOT = Path("engagements")

# Same reasoning as web/server.py's _LOOPBACK_HOSTS: stdio transport is
# inherently local — a client that can spawn `nexus mcp` as a subprocess
# already has equivalent access to this machine, so it needs no separate
# auth. --http mode is a real network listener; run_tool/run_mission can
# trigger real scans and LLM spend, so an unauthenticated network listener
# here is the same class of exposure the dashboard already guards against.
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MCP_TOKEN = os.environ.get("NEXUS_MCP_TOKEN", "").strip()

# `run_mission` starts a full multi-agent OrchestrationEngine run — many LLM
# calls and tool executions, its own thread pool via FlowController. Nothing
# else in the platform caps how many of these can run concurrently (RateGuard
# throttles individual tool calls by target, BudgetGuard tracks spend per
# mission_id once it exists — neither stops an MCP client from calling
# run_mission itself in an unbounded loop). A local semaphore, not a new
# guardrail module: this is resource exhaustion specific to this new,
# repeatable-by-a-remote-client entry point, not a scope/legality decision.
_MAX_CONCURRENT_MISSIONS = int(os.environ.get("NEXUS_MCP_MAX_CONCURRENT_MISSIONS", "2"))


def build_http_app(server: MCPServer):
    """Wrap the server's streamable-HTTP ASGI app with bearer-token auth
    when NEXUS_MCP_TOKEN is set. Building the full OAuth-shaped
    AuthSettings/TokenVerifier this SDK supports is unwarranted complexity
    for a single-operator static-secret case; a plain Starlette middleware
    checking one header is simpler to reason about and test, and matches
    the dashboard's existing _require_token pattern exactly."""
    app = server.streamable_http_app()
    if not MCP_TOKEN:
        return app

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    class _BearerTokenMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            header = request.headers.get("authorization", "")
            scheme, _, presented = header.partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(presented, MCP_TOKEN):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await call_next(request)

    app.add_middleware(_BearerTokenMiddleware)
    return app


def _mission_report_path(mission_id: str) -> Path:
    mission_dir = safe_join(_ENGAGEMENTS_ROOT, safe_slug(mission_id))
    mission_dir.mkdir(parents=True, exist_ok=True)
    return mission_dir / "mcp_report.json"


def create_server() -> MCPServer:
    import anyio

    mission_slots = anyio.Semaphore(_MAX_CONCURRENT_MISSIONS)

    server = MCPServer(
        name="nexus-strike",
        title="NEXUS-STRIKE",
        version=_nexus_version,
        instructions=(
            "NEXUS-STRIKE is an authorized-security-testing platform with "
            "~280 real tools and a multi-agent orchestrator. Every call "
            "here runs through the same Scope/Legal/Escalation/Rate/Audit/"
            "Output guardrails as the CLI: targets must be within "
            "NEXUS_ALLOWED_TARGETS and NEXUS_LEGAL_ACK must be set. Use "
            "list_domains/list_tools/list_agents to discover capabilities, "
            "run_tool for a single check, run_mission for a full "
            "multi-agent assessment, and get_mission_status/get_report to "
            "check on or retrieve a mission you started."
        ),
    )

    @server.tool()
    def list_domains() -> list[str]:
        """List every tool domain (e.g. 'network', 'webapp', 'malware')."""
        from nexus.tools.registry import tool_registry

        domains = {meta.get("domain") for meta in tool_registry.list_tools().values()}
        return sorted(d for d in domains if d)

    @server.tool()
    def list_tools(domain: str | None = None) -> list[dict[str, Any]]:
        """List registered tools, each with its domain, status, description,
        and parameters. Pass `domain` (e.g. 'network') to filter — there are
        ~280 tools total across ~30 domains, so filtering avoids dumping
        everything into context at once."""
        from nexus.tools.registry import tool_registry

        entries = tool_registry.list_tools()
        if domain:
            entries = {k: v for k, v in entries.items() if v.get("domain") == domain}
        return [
            {
                "name": name,
                "domain": meta.get("domain"),
                "status": meta.get("status"),
                "description": meta.get("description"),
                "parameters": meta.get("parameters", {}),
            }
            for name, meta in sorted(entries.items())
        ]

    @server.tool()
    def list_agents(tier: str | None = None) -> list[dict[str, str]]:
        """List registered orchestration agents. Pass `tier`
        (orchestrator/offensive/defensive/analysis/specialized/support) to
        filter to one tier."""
        from nexus.agents.agent_registry import AGENT_REGISTRY, TIER_MAP

        names = AGENT_REGISTRY.keys()
        if tier:
            names = TIER_MAP.get(tier, [])
        results = []
        for name in sorted(names):
            path = AGENT_REGISTRY.get(name, "")
            found_tier = next((t for t, members in TIER_MAP.items() if name in members), None)
            results.append({"name": name, "class_path": path, "tier": found_tier or ""})
        return results

    @server.tool()
    async def run_tool(tool_name: str, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one registered NEXUS-STRIKE tool (see list_tools for names)
        against `target`. Routes through the full guardrail chain — an
        out-of-scope target, missing NEXUS_LEGAL_ACK, or a destructive
        action pending human approval is rejected the same way it would be
        from the CLI, returned as a normal (non-crashing) failed result."""
        from nexus.tools.registry import tool_registry

        return tool_registry.run(tool_name, target, **(params or {}))

    @server.tool()
    async def run_mission(
        target: str,
        mode: str = "guided",
        objective: str = "full_assessment",
        mission_id: str | None = None,
        provider: str | None = None,
        allowed_domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run a full multi-agent NEXUS-STRIKE mission against `target` —
        the same pipeline `nexus run`/`nexus pentest`/`nexus ctf`/etc. use
        (planning, dependency-batched tool execution, verification,
        MITRE mapping, report generation). Mission-level guardrails
        (scope/legal/escalation) apply exactly as they do from the CLI.
        Blocks until the mission completes (this can take a while for a
        real multi-agent assessment); the result is also persisted so a
        later get_report(mission_id) call can retrieve it without
        re-running anything. Rejects cleanly (does not queue) if
        NEXUS_MCP_MAX_CONCURRENT_MISSIONS missions are already running
        through this server — call get_mission_status/retry rather than
        stacking up unbounded concurrent multi-agent runs."""
        import anyio

        from nexus.orchestration.engine import OrchestrationEngine

        try:
            mission_slots.acquire_nowait()
        except anyio.WouldBlock:
            return {
                "status": "failed",
                "error": f"Too many concurrent missions already running via this MCP server "
                         f"(limit: {_MAX_CONCURRENT_MISSIONS}). Wait for one to finish or check "
                         "get_mission_status, then retry.",
            }
        try:
            resolved_mission_id = mission_id or f"mcp-{safe_slug(target)}"
            engine = OrchestrationEngine(llm_provider=provider, emit_events=False)
            result = await engine.run_mission(
                target=target,
                mission_id=resolved_mission_id,
                mode=mode,
                objective=objective,
                allowed_domains=allowed_domains,
            )
        finally:
            mission_slots.release()
        try:
            _mission_report_path(resolved_mission_id).write_text(
                json.dumps(result, default=str, indent=2), encoding="utf-8"
            )
        except OSError:
            pass  # Persistence is a convenience for get_report; the caller already has the result.
        return result

    @server.tool()
    def get_mission_status(mission_id: str) -> dict[str, Any]:
        """Check progress on a mission started via run_mission — reports
        batch-level checkpoint progress if the mission is still running or
        was interrupted, and whether a completed report is available."""
        from nexus.orchestration.recovery.checkpoint import Checkpoint

        checkpoint = Checkpoint().load(mission_id)
        report_available = _mission_report_path(mission_id).exists()
        if checkpoint is None and not report_available:
            return {"mission_id": mission_id, "state": "unknown", "report_available": False}
        if report_available and checkpoint is None:
            return {"mission_id": mission_id, "state": "completed", "report_available": True}
        return {
            "mission_id": mission_id,
            "state": "completed" if report_available else "in_progress_or_interrupted",
            "report_available": report_available,
            "checkpoint": {
                "batch": checkpoint.get("batch") if checkpoint else None,
                "total_batches": checkpoint.get("total_batches") if checkpoint else None,
            },
        }

    @server.tool()
    def get_report(mission_id: str) -> dict[str, Any]:
        """Retrieve the persisted result of a mission previously run via
        run_mission. Returns an `error` field if no report is available
        yet for this mission_id."""
        path = _mission_report_path(mission_id)
        if not path.exists():
            return {"mission_id": mission_id, "error": "No report found for this mission_id yet."}
        return json.loads(path.read_text(encoding="utf-8"))

    return server
