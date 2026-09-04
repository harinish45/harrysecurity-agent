#!/usr/bin/env python3
"""
NEXUS-STRIKE Web Dashboard Server
Strix-style local security platform interface.
"""
import os
import json
import uvicorn
from fastapi import FastAPI, WebSocket, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from nexus.foundation.config import config
from nexus.foundation.paths import PathTraversalError, safe_join
from web.middleware import install_middleware, require_same_origin_signal

app = FastAPI(title="NEXUS-STRIKE Dashboard")
install_middleware(app)

# Mount static files
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── Dashboard token auth ───────────────────────────────────────────────────
# Set NEXUS_DASHBOARD_TOKEN to require Authorization: Bearer <token> on /api/*.
# In production (NEXUS_ENV=production) a token is REQUIRED — the server
# refuses to start without one rather than silently running the whole API
# open to anyone who can reach the port. In development it stays optional
# so `nexus dashboard` keeps working out of the box for local use.
DASHBOARD_TOKEN = os.environ.get("NEXUS_DASHBOARD_TOKEN", "").strip()

if config.is_production and not DASHBOARD_TOKEN:
    raise RuntimeError(
        "NEXUS_ENV=production but NEXUS_DASHBOARD_TOKEN is not set. "
        "Refusing to start an unauthenticated dashboard in production — "
        "set NEXUS_DASHBOARD_TOKEN (see .env.example) or run with "
        "NEXUS_ENV=development for local-only use."
    )


def _bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else ""


def _require_token(request: Request):
    """Raise 401 unless the request is authenticated by EITHER:

    - the shared NEXUS_DASHBOARD_TOKEN (legacy, operator-configured secret —
      treated as full/operator-equivalent access, same as before this file
      had any per-user auth at all), or
    - a valid nexus.foundation.auth session token issued by POST
      /api/auth/login. When it's the latter, the resolved Session is
      attached to request.state.session so _require_permission() below can
      do real RBAC checks; a DASHBOARD_TOKEN request has no Session object
      (request.state.session stays None) since it isn't tied to any one
      user account.
    """
    request.state.session = None
    token = _bearer_token(request)

    if DASHBOARD_TOKEN and token == DASHBOARD_TOKEN:
        return

    if token:
        from nexus.foundation.auth import auth_manager

        session = auth_manager.validate_session(token)
        if session is not None:
            request.state.session = session
            return

    if not DASHBOARD_TOKEN:
        # No shared token configured (development default) and no valid
        # per-user session either — stay open, matching the pre-existing
        # behavior for NEXUS_DASHBOARD_TOKEN being unset.
        return

    raise HTTPException(status_code=401, detail="Missing or invalid dashboard token")


def _require_permission(request: Request, permission) -> None:
    """Real per-user RBAC check — only meaningful for requests authenticated
    via a personal login session (see _require_token). A request using the
    shared NEXUS_DASHBOARD_TOKEN is NOT subject to this check: that token is
    an operator-configured secret that predates per-user accounts and is
    treated as already fully trusted, same as it always was. Call
    _require_token(request) first on every route that uses this."""
    session = getattr(request.state, "session", None)
    if session is None:
        return  # shared-token or auth-disabled request — unchanged behavior
    from nexus.foundation.auth import auth_manager

    try:
        auth_manager.require_permission(session, permission)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@app.post("/api/auth/login")
async def auth_login(payload: dict, request: Request):
    """Authenticate against nexus.foundation.auth (bcrypt + optional TOTP)
    and return a per-user session token. Bootstrap the first account with
    `nexus auth create-admin` — there is no default account."""
    require_same_origin_signal(request)
    from nexus.foundation.auth import AuthenticationError, auth_manager

    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    totp_code = payload.get("totp_code")

    try:
        session = auth_manager.authenticate(username, password, totp_code=totp_code)
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    return {
        "token": session.token,
        "username": session.username,
        "role": session.role.value,
        "expires_at": session.expires_at.isoformat(),
    }


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    _require_token(request)
    require_same_origin_signal(request)
    session = getattr(request.state, "session", None)
    if session is not None:
        from nexus.foundation.auth import auth_manager

        auth_manager.revoke_session(session.token)
    return {"status": "logged_out"}


@app.get("/api/auth/me")
async def auth_me(request: Request):
    """Report the caller's own identity. A DASHBOARD_TOKEN-authenticated
    request (no personal session) reports authenticated=true with no
    username/role, since that token isn't tied to any one account."""
    _require_token(request)  # already gates this route; reaching here means allowed
    session = getattr(request.state, "session", None)
    if session is None:
        # Allowed via the shared DASHBOARD_TOKEN, or no token is configured
        # at all (open development mode) — either way, not tied to one account.
        return {"authenticated": True, "session": False}
    return {
        "authenticated": True,
        "session": True,
        "username": session.username,
        "role": session.role.value,
        "expires_at": session.expires_at.isoformat(),
    }


def _normalize_finding(item):
    """Normalize a raw finding (str or dict) into a canonical dict with a severity key."""
    if isinstance(item, dict):
        sev = str(item.get("severity", "info")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        return {**item, "severity": sev}
    # String finding — treat as a single info finding
    return {
        "title": str(item)[:200],
        "severity": "info",
        "description": str(item),
    }


@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>NEXUS-STRIKE Dashboard</h1><p>Templates not found.</p>")

@app.get("/api/reports")
async def get_reports(request: Request):
    """List all available PDF and JSON reports."""
    _require_token(request)
    reports = []
    if REPORTS_DIR.exists():
        for f in REPORTS_DIR.iterdir():
            if f.suffix in (".pdf", ".json"):
                reports.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "modified": f.stat().st_mtime,
                    "url": f"/api/reports/{f.name}"
                })
    return {"reports": sorted(reports, key=lambda x: x["modified"], reverse=True)}

@app.get("/api/reports/{filename}")
async def get_report(filename: str, request: Request):
    """Serve a specific report file."""
    _require_token(request)
    try:
        file_path = safe_join(REPORTS_DIR, filename)
    except PathTraversalError:
        # Same response as "not found" — don't distinguish a traversal
        # attempt from a typo'd filename for an unauthenticated prober.
        raise HTTPException(status_code=404, detail="Report not found")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    if filename.endswith(".pdf"):
        return FileResponse(file_path, media_type="application/pdf")
    elif filename.endswith(".json"):
        return FileResponse(file_path, media_type="application/json")
    raise HTTPException(status_code=400, detail="Unsupported file type")

@app.get("/api/stats")
async def get_stats(request: Request):
    """Get dashboard statistics from latest report."""
    _require_token(request)
    latest_json = None
    if REPORTS_DIR.exists():
        json_files = sorted([f for f in REPORTS_DIR.iterdir() if f.suffix == ".json"], key=lambda x: x.stat().st_mtime, reverse=True)
        if json_files:
            latest_json = json_files[0]
    
    if latest_json:
        with open(latest_json, "r") as f:
            data = json.load(f)
        findings = data.get("findings", [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            norm = _normalize_finding(f)
            sev = norm.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["info"] += 1
        return {
            "target": data.get("_meta", {}).get("target", "Unknown"),
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "open_ports": data.get("open_ports", []),
            "phases_completed": data.get("_meta", {}).get("phases_completed", 0),
            "findings": [_normalize_finding(f) for f in findings],
        }
    return {"error": "No reports found"}

@app.get("/api/agents")
async def get_agents(request: Request):
    """Get all agents grouped by tier for topology view."""
    _require_token(request)
    try:
        from nexus.agents.agent_registry import get_agents_by_tier, get_agent_count
        return {
            "total": get_agent_count(),
            "by_tier": get_agents_by_tier(),
        }
    except ImportError:
        return {"total": 0, "by_tier": {}}


@app.get("/api/skills")
async def get_skills(request: Request):
    """Get all registered skills from both registries."""
    _require_token(request)
    try:
        from nexus.skills import skills_registry, skill_registry
        return {
            "functional": [s.name for s in skills_registry.list_all()],
            "class_based": skill_registry.list_all(),
            "total": skill_registry.count,
        }
    except ImportError:
        return {"functional": [], "class_based": [], "total": 0}


@app.get("/api/tools")
async def get_tools(request: Request):
    """Get tool counts grouped by domain."""
    _require_token(request)
    try:
        from nexus.tools.registry import get_tool_count_by_domain, get_tool_domains
        return {
            "domains": get_tool_domains(),
            "counts": get_tool_count_by_domain(),
            "total": sum(get_tool_count_by_domain().values()),
        }
    except ImportError:
        return {"domains": [], "counts": {}, "total": 0}


# ── Scan control state (in-process only, resets on restart) ──────────────────
import subprocess as _subprocess
_active_scan: dict = {"process": None, "target": None, "status": "idle"}

# Connected WebSocket clients for real-time scan progress
_ws_clients: list[WebSocket] = []


async def _broadcast_scan_event(event: dict):
    """Send a scan progress event to all connected WebSocket clients."""
    for ws in list(_ws_clients):
        try:
            await ws.send_json(event)
        except Exception:
            if ws in _ws_clients:
                _ws_clients.remove(ws)


def _websocket_auth_check(websocket: WebSocket, query_params: dict) -> bool:
    """Validate token for WebSocket connections if NEXUS_DASHBOARD_TOKEN is set."""
    if not DASHBOARD_TOKEN:
        return True
    token = query_params.get("token", "") or query_params.get("access_token", "")
    if token == DASHBOARD_TOKEN:
        return True
    auth = websocket.headers.get("Authorization", "")
    if auth == f"Bearer {DASHBOARD_TOKEN}":
        return True
    return False


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    """WebSocket endpoint for real-time scan progress streaming."""
    if not _websocket_auth_check(websocket, dict(websocket.query_params)):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        # Send current state immediately on connect
        proc = _active_scan.get("process")
        running = proc is not None and proc.poll() is None
        await websocket.send_json({
            "type": "status",
            "status": "running" if running else _active_scan.get("status", "idle"),
            "target": _active_scan.get("target"),
        })
        while True:
            data = await websocket.receive_text()
            # Client commands are acknowledged; scan control is via REST API
            await websocket.send_json({"type": "ack", "message": data})
    except Exception:
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


@app.websocket("/ws/steer")
async def websocket_steer(websocket: WebSocket):
    """WebSocket endpoint for live scan steering.

    NOTE: this is not yet wired to the scan engine — it acknowledges
    messages but does not act on them. Kept minimal and clearly labeled
    rather than removed, since the dashboard JS references it; do not
    build UI features assuming it does anything beyond echo back an ack.
    """
    if not _websocket_auth_check(websocket, dict(websocket.query_params)):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Acknowledged (not yet actioned): {data}")
    except Exception:
        pass


@app.get("/api/findings")
async def get_findings(request: Request, limit: int = 50):
    """Return findings from the most recent JSON report."""
    _require_token(request)
    if not REPORTS_DIR.exists():
        return {"findings": [], "total": 0, "target": None}

    json_files = sorted(
        [f for f in REPORTS_DIR.iterdir() if f.suffix == ".json"],
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )
    if not json_files:
        return {"findings": [], "total": 0, "target": None}

    with open(json_files[0], "r", encoding="utf-8") as fh:
        data = json.load(fh)

    raw_findings = data.get("findings", [])
    findings = [_normalize_finding(f) for f in raw_findings]
    return {
        "findings": findings[:limit],
        "total": len(findings),
        "target": data.get("_meta", {}).get("target"),
        "report": json_files[0].name,
    }


@app.get("/api/config")
async def get_config(request: Request):
    """Return current platform configuration (safe, no secrets)."""
    _require_token(request)
    try:
        from nexus.foundation.config import config
        return {
            "ollama_base_url": getattr(config, "ollama_base_url", "http://localhost:11434/v1"),
            "ollama_model":    getattr(config, "ollama_model", "qwen2.5-coder:7b"),
            "reports_dir":     str(REPORTS_DIR),
        }
    except ImportError:
        return {"error": "config not available"}


@app.post("/api/config")
async def update_config(payload: dict, request: Request):
    """Placeholder for future config write support."""
    _require_token(request)
    require_same_origin_signal(request)
    from nexus.foundation.auth import Permission

    _require_permission(request, Permission.CONFIG_WRITE)
    return {"status": "accepted", "note": "Runtime config changes not yet persisted"}


# Minimal environment for the spawned `nexus live` subprocess — NOT a blind
# copy of the dashboard server's own os.environ, which could otherwise hand
# the child process every LLM API key, DB credential, etc. the parent has
# loaded, whether that scan needs them or not (CWE-200-adjacent exposure).
_SCAN_ENV_ALLOWLIST = {
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "HOME", "USERPROFILE",
    "LANG", "LC_ALL", "TZ", "NEXUS_ENV", "NEXUS_LOG_LEVEL", "NEXUS_LEGAL_ACK",
    "NEXUS_ALLOWED_TARGETS", "NEXUS_MASTER_KEY", "NEXUS_VAULT_DIR",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "LLM_PROVIDER",
}


@app.post("/api/scan/start")
async def scan_start(payload: dict, request: Request):
    """Launch nexus live in a background subprocess for the given target."""
    _require_token(request)
    require_same_origin_signal(request)
    from nexus.foundation.auth import Permission

    _require_permission(request, Permission.SCAN_CREATE)
    global _active_scan
    target = payload.get("target", "127.0.0.1")

    if not os.environ.get("NEXUS_LEGAL_ACK"):
        # Used to be auto-injected here on every scan, which defeats its
        # purpose as an explicit authorization gate — an operator must now
        # actually set it (see .env.example) before the dashboard can scan.
        raise HTTPException(
            status_code=403,
            detail="NEXUS_LEGAL_ACK is not set. Set it in the server's environment to confirm "
                   "you have written authorization to scan targets before starting a scan.",
        )

    try:
        from nexus.foundation.guardrails import InputGuard, ScopeGuard

        InputGuard.validate(target, context={"source": "dashboard.scan_start"})
        ScopeGuard.validate(target)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Target rejected: {exc}")

    if _active_scan["process"] and _active_scan["process"].poll() is None:
        return {"status": "already_running", "target": _active_scan["target"]}

    import sys as _sys

    # Notify clients that a scan is starting
    _active_scan = {"process": None, "target": target, "status": "starting"}
    await _broadcast_scan_event({"type": "phase", "target": target, "phase": 0, "message": "Scan starting…"})

    cmd = [_sys.executable, "-m", "nexus", "live", "--target", target]
    scan_env = {k: v for k, v in os.environ.items() if k in _SCAN_ENV_ALLOWLIST}
    proc = _subprocess.Popen(
        cmd,
        stdout=_subprocess.PIPE,
        stderr=_subprocess.STDOUT,
        text=True,
        env=scan_env,
    )
    _active_scan = {"process": proc, "target": target, "status": "running"}
    await _broadcast_scan_event({"type": "status", "status": "running", "target": target})

    # Background reader: stream stdout lines to WebSocket clients
    import threading

    def _stream_output(process):
        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue
            # Broadcast progress
            import asyncio
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(_broadcast_scan_event({"type": "output", "target": target, "line": line}))
                loop.close()
            except Exception:
                pass

    threading.Thread(target=_stream_output, args=(proc,), daemon=True).start()

    return {"status": "started", "target": target, "pid": proc.pid}


@app.post("/api/scan/stop")
async def scan_stop(request: Request):
    """Terminate any running background scan."""
    _require_token(request)
    require_same_origin_signal(request)
    from nexus.foundation.auth import Permission

    _require_permission(request, Permission.SCAN_STOP)
    global _active_scan
    proc = _active_scan.get("process")
    if proc and proc.poll() is None:
        proc.terminate()
        _active_scan["status"] = "stopped"
        await _broadcast_scan_event({"type": "status", "status": "stopped", "target": _active_scan.get("target")})
        return {"status": "stopped"}
    return {"status": "no_active_scan"}


@app.get("/api/scan/status")
async def scan_status(request: Request):
    """Return current scan status."""
    _require_token(request)
    proc = _active_scan.get("process")
    running = proc is not None and proc.poll() is None
    return {
        "status": "running" if running else _active_scan.get("status", "idle"),
        "target": _active_scan.get("target"),
        "pid": proc.pid if proc and running else None,
    }


@app.post("/api/agent/run")
async def agent_run(payload: dict, request: Request):
    """Run one agent's real run() against a target directly — the dashboard
    equivalent of `nexus agent run <name> --target <t>`. This is the only
    way the orchestrator-tier planning/routing agents (mission_commander_
    agent, task_planner_agent, agent_router_agent) are reachable from the
    dashboard: their job is to produce a plan or a routing decision, not to
    be one phase of a FlowController-run mission themselves, so they aren't
    wired into /api/scan/start.
    """
    _require_token(request)
    require_same_origin_signal(request)
    from nexus.foundation.auth import Permission

    _require_permission(request, Permission.SCAN_CREATE)

    from nexus.agents.agent_registry import get_agent
    from nexus.foundation.guardrails import EscalationGuard, LegalGuard, ScopeGuard

    agent_name = str(payload.get("agent", ""))
    target = str(payload.get("target", ""))
    task = str(payload.get("task") or f"Run {agent_name} against {target}")

    try:
        agent_cls = get_agent(agent_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown agent '{agent_name}'")

    if not os.environ.get("NEXUS_LEGAL_ACK"):
        raise HTTPException(
            status_code=403,
            detail="NEXUS_LEGAL_ACK is not set. Set it in the server's environment to confirm "
                   "you have written authorization to scan targets before running an agent.",
        )

    try:
        ScopeGuard.validate(target)
        LegalGuard.validate(target=target)
        EscalationGuard.validate(f"agent_{agent_name}", "execute")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Guardrail blocked: {exc}")

    agent = agent_cls()
    result = await agent.run(task, target=target)
    # Normalise: agents built on tool_result() key their own name under
    # "tool" (matching the tool-execution schema they reuse), not "agent" —
    # this is the one place a caller shouldn't need to know which internal
    # convention a given agent happens to follow.
    result.setdefault("agent", agent_name)
    return result


def _open_browser_safe(url: str) -> None:
    """Open the browser safely; never crash in headless environments."""
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        # Headless / no display — log a helpful message instead of crashing
        print(f"[nexus] Browser could not be opened automatically. "
              f"Visit {url} manually.")


def launch_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Launch the Strix dashboard and optionally open the browser."""
    url = f"http://{host}:{port}"
    if open_browser:
        import threading
        # Open browser after a short delay so the server is ready
        threading.Timer(1.5, lambda: _open_browser_safe(url)).start()
    print(f"[nexus] 🖥️ Dashboard available at: {url}")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    launch_dashboard()