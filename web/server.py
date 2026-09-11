"""NEXUS-STRIKE local security dashboard server."""
import asyncio
import json
import os
import subprocess
import threading
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from nexus.foundation.config import config
from nexus.foundation.guardrails import InputGuard, LegalGuard, ScopeGuard
from nexus.foundation.paths import PathTraversalError, safe_join
from web.middleware import install_middleware, require_same_origin_signal
from web.mission_api import router as mission_router

app = FastAPI(title="NEXUS-STRIKE Dashboard")
install_middleware(app)

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
# Mission-control API (create/list/transition missions, event replay). This
# router was added in the mission-control merge but the include_router call
# that exposes it was dropped somewhere in that same merge — it shipped with
# passing unit tests (tests/unit/test_mission.py) for the underlying
# Mission/MissionStore model, but the HTTP layer in web/mission_api.py was
# unreachable from this app: nothing mounted it, so every endpoint below
# /api/missions 404'd regardless of auth. Restored so the feature the tests
# already exercise is actually reachable. mission_api.py's _require_token/
# _require_permission delegate directly to this module's own functions (see
# web/mission_api.py) rather than maintaining a second auth implementation,
# so mounting it does not open any endpoint with weaker protection than the
# rest of this file's /api/* routes.
app.include_router(mission_router)

# ── Dashboard token auth ───────────────────────────────────────────────────
# Set NEXUS_DASHBOARD_TOKEN to require Authorization: Bearer <token> on /api/*.
# In production (NEXUS_ENV=production) a token is REQUIRED — the server
# refuses to start without one rather than silently running the whole API
# open to anyone who can reach the port. In development it stays optional
# so `nexus dashboard` keeps working out of the box for local use.
DASHBOARD_TOKEN = os.environ.get("NEXUS_DASHBOARD_TOKEN", "").strip()

# ── Proxy header trust ─────────────────────────────────────────────────────
# uvicorn.run()'s own defaults (proxy_headers=True, forwarded_allow_ips=
# "127.0.0.1") let ANY client whose direct TCP peer address is 127.0.0.1
# rewrite request.client via X-Forwarded-For, before FastAPI/Starlette ever
# see the request — RateGuard.validate(target=f"login:{client_host}") above
# then keys its per-IP rate limit off that attacker-controlled value. That's
# correct behavior ONLY when a real, trusted reverse proxy is what's
# actually connecting from 127.0.0.1; nexus-strike isn't documented to run
# behind one, and this app usually binds loopback itself, so the same-host
# co-located-process case (anything else able to open a loopback socket,
# e.g. a sidecar) could otherwise spoof its source IP for free. Default to
# NOT trusting forwarded headers; an operator who does front this with nginx
# etc. can opt in explicitly.
TRUST_PROXY_HEADERS = os.environ.get("NEXUS_TRUST_PROXY_HEADERS", "").strip().lower() in (
    "1", "true", "yes",
)
TRUSTED_PROXY_IPS = os.environ.get("NEXUS_TRUSTED_PROXY_IPS", "127.0.0.1").strip()

_subprocess = subprocess
_active_scan = {"process": None, "target": None, "status": "idle"}
_ws_clients: set[WebSocket] = set()
_ws_loop: asyncio.AbstractEventLoop | None = None

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
    `nexus auth create-admin` — there is no default account.

    ``AuthManager``'s per-account lockout (5 attempts / 15 min) stops a
    brute-force run against ONE username, but does nothing against a
    credential-spray sweeping many different usernames from one source —
    each guess lands under a different account's own attempt counter. This
    endpoint adds a second, IP-keyed layer via the same ``RateGuard`` used
    to bound every other target-facing call in this codebase, so a spray
    attempt gets rate-limited overall regardless of which username it's
    currently trying.
    """
    require_same_origin_signal(request)
    from nexus.foundation.auth import AuthenticationError, auth_manager
    from nexus.foundation.guardrails.rate_guard import RateGuard, RateGuardError

    client_host = request.client.host if request.client else "unknown"
    try:
        RateGuard.validate(target=f"login:{client_host}")
    except RateGuardError as exc:
        raise HTTPException(status_code=429, detail=str(exc))

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
    if isinstance(item, dict):
        severity = str(item.get("severity", "info")).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"
        return {**item, "severity": severity}
    return {"title": str(item)[:200], "severity": "info", "description": str(item)}


@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>NEXUS-STRIKE Dashboard</h1><p>Templates not found.</p>")

_SERVABLE_REPORT_TYPES = {
    ".pdf": "application/pdf",
    ".json": "application/json",
    ".md": "text/markdown",
}


@app.get("/api/reports")
async def get_reports(request: Request):
    """List all available report files (PDF, JSON, or Markdown)."""
    _require_token(request)
    reports = []
    if REPORTS_DIR.exists():
        for f in REPORTS_DIR.iterdir():
            if f.suffix in _SERVABLE_REPORT_TYPES:
                reports.append({
                    "name": f.name,
                    "size": f.stat().st_size,
                    "modified": f.stat().st_mtime,
                    "url": f"/api/reports/{f.name}"
                })
    return {"reports": sorted(reports, key=lambda x: x["modified"], reverse=True)}


@app.get("/api/reports/{filename}")
async def get_report(filename: str, request: Request):
    _require_token(request)
    try:
        file_path = safe_join(REPORTS_DIR, filename)
    except PathTraversalError:
        # Same response as "not found" — don't distinguish a traversal
        # attempt from a typo'd filename for an unauthenticated prober.
        raise HTTPException(status_code=404, detail="Report not found")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = _SERVABLE_REPORT_TYPES.get(file_path.suffix)
    if media_type is None:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    return FileResponse(file_path, media_type=media_type)

@app.get("/api/stats")
async def get_stats(request: Request):
    _require_token(request)
    json_files = sorted([p for p in REPORTS_DIR.glob("*.json") if p.is_file()],
                        key=lambda p: p.stat().st_mtime, reverse=True) if REPORTS_DIR.exists() else []
    if not json_files:
        return {"error": "No reports found"}
    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    severity_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    normalized = [_normalize_finding(f) for f in findings]
    for finding in normalized:
        severity_counts[finding["severity"]] += 1
    return {"target": data.get("_meta", {}).get("target", "Unknown"),
            "total_findings": len(findings), "severity_counts": severity_counts,
            "open_ports": data.get("open_ports", []),
            "phases_completed": data.get("_meta", {}).get("phases_completed", 0),
            "findings": normalized}


@app.get("/api/agents")
async def get_agents(request: Request):
    _require_token(request)
    from nexus.agents.agent_registry import get_agent_count, get_agents_by_tier
    return {"total": get_agent_count(), "by_tier": get_agents_by_tier()}


@app.get("/api/skills")
async def get_skills(request: Request):
    _require_token(request)
    from nexus.skills import skill_registry, skills_registry
    return {"functional": [skill.name for skill in skills_registry.list_all()],
            "class_based": skill_registry.list_all(), "total": skill_registry.count}


@app.get("/api/tools")
async def get_tools(request: Request):
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
# `_active_scan`/`_ws_clients` are already declared at module scope above (a
# set, since .add()/.discard() are used on it below — a stray duplicate
# `list[...] = []` re-declaration here previously existed and would have
# crashed the first real .add()/.discard() call with AttributeError; removed,
# not re-declared).
#
# Guards the check-then-act sequence in scan_start(): without this, two
# concurrent POSTs to /api/scan/start can both pass the "already running"
# check (there's an `await` between the check and the point where
# _active_scan is actually populated with the new subprocess handle) and
# both spawn a subprocess, with the loser's process left untracked/orphaned.
# Must be held across every await in that section so a second request
# blocks until the first has fully published its new state, then re-checks
# it — not just around the synchronous read/write.
_active_scan_lock = asyncio.Lock()

# Cap on concurrent WebSocket connections, enforced separately for /ws/scan
# and /ws/steer. Without this, any client that can reach the port (trivially
# true when NEXUS_DASHBOARD_TOKEN is unset, the documented dev default) can
# open unbounded connections in a loop, each holding an OS socket fd + asyncio
# task, exhausting the server process's fd limit and taking the whole
# dashboard down (EMFILE) for everyone else. A valid token only gates who can
# connect, not how many times, so the cap applies regardless of auth state.
WS_MAX_CONNECTIONS = int(os.environ.get("NEXUS_WS_MAX_CONNECTIONS", "100"))

# /ws/steer has no client list of its own (it doesn't broadcast), so track
# just a count for its cap.
_ws_steer_count = 0


async def _broadcast_scan_event(event: dict):
    stale = []
    for websocket in list(_ws_clients):
        try:
            await websocket.send_json(event)
        except Exception:
            stale.append(websocket)
    for websocket in stale:
        _ws_clients.discard(websocket)


# Application-level cap on a single incoming WebSocket text frame. This is
# enforced here rather than relying solely on uvicorn's transport-level
# ws_max_size: uvicorn's default is 16 MiB and launch_dashboard()'s
# uvicorn.run() call never overrode it, so an authenticated (or, in the
# common no-token dev config, any) client could stream near-16MB frames
# back-to-back — with uvicorn's default ws_max_queue=32 letting up to ~32
# of them queue per connection — driving memory usage up sharply with no
# server-side circuit breaker. Checking length here also protects the
# ASGI test transport (TestClient), which doesn't go through uvicorn's
# websocket frame parser at all.
MAX_WS_MESSAGE_BYTES = 65536  # 64 KiB — these endpoints only ever carry
# small control/ack JSON payloads, never scan output (that's pushed via
# _ws_clients broadcast, not read from the client).


def _broadcast_from_worker(event: dict):
    if _ws_loop and _ws_loop.is_running():
        asyncio.run_coroutine_threadsafe(_broadcast_scan_event(event), _ws_loop)


def _websocket_auth_check(websocket: WebSocket, params: dict | None = None) -> bool:
    """Validate credentials from query parameters or an Authorization header."""
    if not DASHBOARD_TOKEN:
        return True
    params = params or {}
    query_params = getattr(websocket, "query_params", {})
    token = (params.get("token") or params.get("access_token") or
             query_params.get("token", "") or query_params.get("access_token", ""))
    return token == DASHBOARD_TOKEN or websocket.headers.get("Authorization", "") == f"Bearer {DASHBOARD_TOKEN}"


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    global _ws_loop
    if not _websocket_auth_check(websocket):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    if len(_ws_clients) >= WS_MAX_CONNECTIONS:
        await websocket.close(code=1013, reason="Too many connections")
        return
    await websocket.accept()
    _ws_loop = asyncio.get_running_loop()
    _ws_clients.add(websocket)
    try:
        process = _active_scan.get("process")
        running = process is not None and process.poll() is None
        await websocket.send_json({"type": "status", "status": "running" if running else _active_scan.get("status", "idle"),
                                   "target": _active_scan.get("target")})
        while True:
            data = await websocket.receive_text()
            if len(data.encode("utf-8")) > MAX_WS_MESSAGE_BYTES:
                await websocket.close(code=1009, reason="Message too big")
                break
            # Client commands are acknowledged; scan control is via REST API
            await websocket.send_json({"type": "ack", "message": data})
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)


@app.websocket("/ws/steer")
async def websocket_steer(websocket: WebSocket):
    """WebSocket endpoint for live scan steering.

    NOTE: this is not yet wired to the scan engine — it acknowledges
    messages but does not act on them. Kept minimal and clearly labeled
    rather than removed, since the dashboard JS references it; do not
    build UI features assuming it does anything beyond echo back an ack.
    """
    global _ws_steer_count
    if not _websocket_auth_check(websocket, dict(websocket.query_params)):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    if _ws_steer_count >= WS_MAX_CONNECTIONS:
        await websocket.close(code=1013, reason="Too many connections")
        return
    await websocket.accept()
    _ws_steer_count += 1
    try:
        while True:
            data = await websocket.receive_text()
            if len(data.encode("utf-8")) > MAX_WS_MESSAGE_BYTES:
                await websocket.close(code=1009, reason="Message too big")
                break
            await websocket.send_text(f"Acknowledged (not yet actioned): {data}")
    except Exception:
        pass
    finally:
        _ws_steer_count -= 1


def _latest_report_findings() -> tuple[list[dict], dict]:
    """Findings + `_meta` from the most recent JSON report, normalized —
    shared by /api/findings and the newer mission-analysis endpoints below
    (MITRE coverage, attack graph, report-tone preview) so they all read
    the same "latest mission" source of truth."""
    if not REPORTS_DIR.exists():
        return [], {}
    json_files = sorted(
        [f for f in REPORTS_DIR.iterdir() if f.suffix == ".json"],
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )
    if not json_files:
        return [], {}
    with open(json_files[0], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    findings = [_normalize_finding(f) for f in data.get("findings", [])]
    meta = {**data.get("_meta", {}), "report": json_files[0].name}
    return findings, meta


@app.get("/api/findings")
async def get_findings(request: Request, limit: int = 50):
    """Return findings from the most recent JSON report."""
    _require_token(request)
    if not 1 <= limit <= 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    findings, meta = _latest_report_findings()
    return {
        "findings": findings[:limit],
        "total": len(findings),
        "target": meta.get("target"),
        "report": meta.get("report"),
    }


@app.get("/api/mitre-coverage")
async def get_mitre_coverage(request: Request):
    """MITRE ATT&CK technique coverage across the latest mission's findings
    — feeds the dashboard's MITRE heat-map panel. Technique tags come from
    `mitre_mapping_agent`; a finding with none simply doesn't contribute."""
    _require_token(request)
    findings, meta = _latest_report_findings()
    coverage: dict[str, dict] = {}
    for f in findings:
        for t in f.get("mitre_techniques") or []:
            tid = t.get("id", "?")
            entry = coverage.setdefault(tid, {"id": tid, "name": t.get("name", ""), "count": 0, "max_severity": "info"})
            entry["count"] += 1
            severities = ["critical", "high", "medium", "low", "info"]
            sev = f.get("severity", "info")
            if sev in severities and severities.index(sev) < severities.index(entry["max_severity"]):
                entry["max_severity"] = sev
    return {"target": meta.get("target"), "techniques": sorted(coverage.values(), key=lambda e: -e["count"])}


@app.get("/api/attack-graph")
async def get_attack_graph(request: Request):
    """Render the latest mission's findings as an attack-graph SVG (same
    renderer the HTML report export uses) for the dashboard's Attack Graph
    view — a live look at the same visualization, not a separate model."""
    _require_token(request)
    from nexus.reporting.visualizations.attack_graph_viz import AttackGraphViz

    findings, meta = _latest_report_findings()
    svg = AttackGraphViz().render(findings)
    return {"target": meta.get("target"), "svg": svg, "finding_count": len(findings)}


@app.get("/api/report-tone")
async def get_report_tone(request: Request, mode: str = "pentest"):
    """Render the latest mission's findings through `report_tone_agent` for
    the given mode — powers the dashboard's Report Viewer (tabs across
    pentest/bounty/ctf/redteam/blueteam/compliance, same underlying finding
    data, different prose)."""
    _require_token(request)
    from nexus.agents.orchestrator.report_tone_agent import ReportToneAgent

    findings, meta = _latest_report_findings()
    result = await ReportToneAgent().run("Render report preview", target=meta.get("target", ""),
                                          mode=mode, findings=findings)
    return {"mode": mode, "target": meta.get("target"), "report": result.get("metadata", {}).get("rendered_report", "")}


@app.get("/api/budget")
async def get_budget(request: Request, mission_id: str = ""):
    """Live estimated LLM spend for a mission — powers the dashboard's
    budget meter. Without a `mission_id`, returns the active scan's mission
    id if one is running (mission-mode launches use `dashboard-<mode>-<ts>`
    — see `scan_start`).

    Mission-mode scans run in a separate subprocess with their own
    in-memory BudgetGuard — this server process's own BudgetGuard is never
    touched by them. `_stream_output` captures each `budget_update`
    NEXUS-EVENT the subprocess emits into `_active_scan["budget"]`; prefer
    that live snapshot for the currently-active mission, and fall back to
    this process's own BudgetGuard (correct for e.g. /api/agent/run, which
    executes in-process) otherwise."""
    _require_token(request)
    from nexus.foundation.guardrails.budget_guard import BudgetGuard

    mid = mission_id or _active_scan.get("mission_id", "")
    caps = {
        "max_tokens": int(os.environ["NEXUS_BUDGET_MAX_TOKENS"]) if os.environ.get("NEXUS_BUDGET_MAX_TOKENS") else None,
        "max_usd": float(os.environ["NEXUS_BUDGET_MAX_USD"]) if os.environ.get("NEXUS_BUDGET_MAX_USD") else None,
    }
    if not mid:
        return {"mission_id": None, "calls": 0, "estimated_tokens": 0, "estimated_usd": 0.0, **caps}
    if mid == _active_scan.get("mission_id") and _active_scan.get("budget"):
        return {**_active_scan["budget"], **caps}
    return {**BudgetGuard.report(mid), **caps}


@app.get("/api/benchmarks")
async def get_benchmarks(request: Request, limit: int = 50):
    """Score-over-time data for the Benchmark Dashboard, read from
    `benchmarks/history.jsonl` (appended to by `nexus benchmark` /
    `benchmark_harness_agent`) — data path first, chart rendering is a
    client-side concern the frontend can layer on top of this."""
    _require_token(request)
    history_path = Path("benchmarks") / "history.jsonl"
    if not history_path.exists():
        return {"runs": [], "total": 0}

    runs = []
    with history_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                runs.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    runs.sort(key=lambda r: r.get("run_at", ""), reverse=True)
    return {"runs": runs[:limit], "total": len(runs)}


def _read_jsonl_history(path: Path, limit: int) -> dict:
    """Shared reader for the benchmark history sidecars — same tolerant
    read-newest-first behavior as `get_benchmarks` above, factored out so
    the latency/debate-eval endpoints don't duplicate it."""
    if not path.exists():
        return {"runs": [], "total": 0}
    runs = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                runs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    runs.sort(key=lambda r: r.get("run_at", ""), reverse=True)
    return {"runs": runs[:limit], "total": len(runs)}


@app.get("/api/benchmarks/latency")
async def get_benchmarks_latency(request: Request, limit: int = 20):
    """Agent execution-latency history, read from
    `benchmarks/latency_history.jsonl` (appended to by
    `benchmark_agent_latency()` in nexus/benchmarks/agent_eval.py)."""
    _require_token(request)
    return _read_jsonl_history(Path("benchmarks") / "latency_history.jsonl", limit)


@app.get("/api/benchmarks/debate-eval")
async def get_benchmarks_debate_eval(request: Request, limit: int = 20):
    """debate_consensus_agent precision/recall/F1 evaluation history, read
    from `benchmarks/debate_eval_history.jsonl` (appended to by
    `evaluate_debate_consensus()` in nexus/benchmarks/agent_eval.py)."""
    _require_token(request)
    return _read_jsonl_history(Path("benchmarks") / "debate_eval_history.jsonl", limit)


@app.get("/api/config")
async def get_config(request: Request):
    _require_token(request)
    from nexus.foundation.config import config
    return {"ollama_base_url": getattr(config, "ollama_base_url", "http://localhost:11434/v1"),
            "ollama_model": getattr(config, "ollama_model", "qwen2.5-coder:7b"), "reports_dir": str(REPORTS_DIR)}


@app.post("/api/config")
async def update_config(payload: dict, request: Request):
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

# Mission modes the "Mission Control" mode switcher can launch, alongside the
# original legacy `nexus live` scanner (kept as "live" for backward
# compatibility with the existing dashboard UI/scans).
_MISSION_MODES = {"pentest", "bounty", "ctf", "redteam", "blueteam"}


@app.post("/api/scan/start")
async def scan_start(payload: dict, request: Request):
    _require_token(request)
    require_same_origin_signal(request)
    from nexus.foundation.auth import Permission

    _require_permission(request, Permission.SCAN_CREATE)
    global _active_scan
    target = payload.get("target", "127.0.0.1")
    mode = payload.get("mode", "live")
    if not isinstance(mode, str) or (mode != "live" and mode not in _MISSION_MODES):
        raise HTTPException(status_code=400, detail=f"Unknown mode '{mode}'. Available: live, {', '.join(sorted(_MISSION_MODES))}")

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

    # Hold the lock across the whole check-then-act sequence, INCLUDING the
    # `await _broadcast_scan_event(...)` below. Without this, that await is
    # a suspension point between the "already running?" check and the point
    # where _active_scan is populated with the new subprocess handle — two
    # concurrent POSTs could both pass the check while _active_scan still
    # looked idle/"starting", and both go on to spawn and independently
    # overwrite _active_scan, orphaning whichever process lost the race
    # (never visible to /api/scan/status or /api/scan/stop again). Because
    # this is an asyncio.Lock, a second request that arrives while the first
    # is inside this block simply awaits its turn instead of racing it, and
    # then re-runs the same check against the now fully-updated state.
    async with _active_scan_lock:
        if _active_scan["process"] and _active_scan["process"].poll() is None:
            return {"status": "already_running", "target": _active_scan["target"]}
        if _active_scan.get("status") == "starting":
            # Another request already claimed the slot and is still in the
            # middle of spawning its subprocess (process handle not set yet).
            return {"status": "already_running", "target": _active_scan.get("target")}

        import sys as _sys
        import time as _time

        # Notify clients that a scan is starting
        _active_scan = {"process": None, "target": target, "status": "starting", "mode": mode}
        await _broadcast_scan_event({"type": "phase", "target": target, "phase": 0, "message": "Scan starting…", "mode": mode})

        scan_env = {k: v for k, v in os.environ.items() if k in _SCAN_ENV_ALLOWLIST}
        mission_id = None
        if mode == "live":
            cmd = [_sys.executable, "-m", "nexus", "live", "--target", target]
        else:
            # Mission-mode launch — same OrchestrationEngine pipeline as the CLI
            # (`nexus pentest/bounty/ctf/redteam/blueteam`), with structured
            # per-agent progress events turned on so `_stream_output` below can
            # relay real batch/agent progress instead of only raw text lines.
            mission_id = f"dashboard-{mode}-{int(_time.time())}"
            cmd = [_sys.executable, "-m", "nexus", mode, "--target", target, "--mission", mission_id]
            scan_env["NEXUS_EMIT_EVENTS"] = "1"
        proc = _subprocess.Popen(
            cmd,
            stdout=_subprocess.PIPE,
            stderr=_subprocess.STDOUT,
            text=True,
            env=scan_env,
        )
        _active_scan = {"process": proc, "target": target, "status": "running", "mode": mode, "mission_id": mission_id}
        await _broadcast_scan_event({"type": "status", "status": "running", "target": target, "mode": mode})

    # Background reader: stream stdout lines to WebSocket clients. Lines
    # tagged `NEXUS-EVENT:{json}` (emitted by OrchestrationEngine/
    # FlowController when NEXUS_EMIT_EVENTS=1) become structured
    # `agent_event` messages; everything else is relayed as raw `output`,
    # same as before.
    import threading

    def _stream_output(process):
        import asyncio

        def _broadcast(event):
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(_broadcast_scan_event(event))
                loop.close()
            except Exception:
                pass

        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue
            event = {"type": "output", "target": target, "line": line}
            if line.startswith("NEXUS-EVENT:"):
                try:
                    inner = json.loads(line[len("NEXUS-EVENT:"):])
                    event = {"type": "agent_event", "target": target, "event": inner}
                    if inner.get("type") == "budget_update" and _active_scan.get("process") is process:
                        # Mission-mode scans run in this subprocess, with
                        # their own in-memory BudgetGuard the dashboard
                        # server process can never see directly — capture
                        # the snapshot here so GET /api/budget can serve
                        # real numbers instead of always reading 0 for a
                        # running mission (see engine.py's emit_events).
                        #
                        # The identity check mirrors the final-status write
                        # below (`_active_scan.get("process") is process`):
                        # this reader thread keeps consuming buffered stdout
                        # lines for a little while after its own subprocess
                        # is terminated/superseded (e.g. POST /api/scan/stop
                        # followed immediately by a new /api/scan/start), so
                        # without it a stale budget_update from an old/
                        # orphaned mission could clobber the snapshot that
                        # GET /api/budget serves for the mission that is
                        # actually active now.
                        _active_scan["budget"] = inner
                except json.JSONDecodeError:
                    pass
            _broadcast(event)

        # The stdout loop above only ends when the subprocess exits (clean
        # completion, failure, or crash) — nothing previously told connected
        # clients that happened. `_active_scan["status"]` only ever changed
        # via the explicit POST /api/scan/stop, so a mission that finished
        # normally left the dashboard UI believing it was still "running"
        # until someone manually re-polled /api/scan/status.
        returncode = process.wait()
        final_status = "completed" if returncode == 0 else "failed"
        if _active_scan.get("process") is process:
            _active_scan["status"] = final_status
        _broadcast({"type": "status", "status": final_status, "target": target, "mode": mode, "returncode": returncode})

    threading.Thread(target=_stream_output, args=(proc,), daemon=True).start()

    return {"status": "started", "target": target, "mode": mode, "pid": proc.pid}


@app.post("/api/scan/stop")
async def scan_stop(request: Request):
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
    _require_token(request)
    process = _active_scan.get("process")
    running = process is not None and process.poll() is None
    return {"status": "running" if running else _active_scan.get("status", "idle"),
            "target": _active_scan.get("target"), "pid": process.pid if process and running else None}


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
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        print(f"[nexus] Browser could not be opened automatically. Visit {url} manually.")


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def launch_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Launch the Strix dashboard and optionally open the browser.

    The default-open auth behavior in _require_token (no DASHBOARD_TOKEN set
    -> unauthenticated access allowed) is only safe when the server can't be
    reached from outside this machine. is_production already refuses to
    start without a token; this closes the other way an operator could
    expose an unauthenticated dashboard — binding to a non-loopback host
    (e.g. --host 0.0.0.0) in dev mode, where is_production never fires."""
    if host not in _LOOPBACK_HOSTS and not DASHBOARD_TOKEN:
        raise RuntimeError(
            f"Refusing to bind the dashboard to non-loopback host {host!r} "
            "without NEXUS_DASHBOARD_TOKEN set — this would expose an "
            "unauthenticated dashboard to the network. Set "
            "NEXUS_DASHBOARD_TOKEN (see .env.example) or use "
            "--host 127.0.0.1 for local-only use."
        )
    url = f"http://{host}:{port}"
    if open_browser:
        threading.Timer(1.5, lambda: _open_browser_safe(url)).start()
    print(f"[nexus] 🖥️ Dashboard available at: {url}")
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",
        # See TRUST_PROXY_HEADERS above — off by default so request.client
        # (and therefore RateGuard's per-IP key) can't be spoofed via
        # X-Forwarded-For by anything that can merely reach the loopback
        # interface. Set NEXUS_TRUST_PROXY_HEADERS=1 (and optionally
        # NEXUS_TRUSTED_PROXY_IPS) only when a real reverse proxy fronts
        # this server.
        proxy_headers=TRUST_PROXY_HEADERS,
        forwarded_allow_ips=TRUSTED_PROXY_IPS if TRUST_PROXY_HEADERS else [],
        # Cap a single incoming WebSocket frame at the transport layer too
        # (defense in depth alongside the MAX_WS_MESSAGE_BYTES check in the
        # handlers themselves) — uvicorn's default is 16 MiB, which combined
        # with its default ws_max_queue=32 lets ~512 MB queue up in flight
        # on one connection with nothing here to reject it earlier.
        ws_max_size=MAX_WS_MESSAGE_BYTES,
        ws_max_queue=8,
        # Defense in depth alongside the WS_MAX_CONNECTIONS check in the
        # handlers: this bounds ALL concurrent in-flight connections (HTTP
        # and WebSocket) at the ASGI-server layer, so a client can't route
        # around the per-endpoint counters by hitting both endpoints (or
        # HTTP routes) at once and still exhaust the process's fd limit.
        limit_concurrency=WS_MAX_CONNECTIONS * 4,
    )


if __name__ == "__main__":
    launch_dashboard()
