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

app = FastAPI(title="NEXUS-STRIKE Dashboard")

# Mount static files
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── Dashboard token auth (optional) ───────────────────────────────────────────
# Set NEXUS_DASHBOARD_TOKEN to require Authorization: Bearer <token> on /api/*
DASHBOARD_TOKEN = os.environ.get("NEXUS_DASHBOARD_TOKEN", "").strip()


def _require_token(request: Request):
    """Raise 401 if NEXUS_DASHBOARD_TOKEN is set and the request is unauthenticated."""
    if not DASHBOARD_TOKEN:
        return
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {DASHBOARD_TOKEN}":
        raise HTTPException(status_code=401, detail="Missing or invalid dashboard token")


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
    file_path = REPORTS_DIR / filename
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
    """WebSocket endpoint for live scan steering."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back acknowledgment (real implementation would route to scan engine)
            await websocket.send_text(f"Acknowledged: {data}")
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
    return {"status": "accepted", "note": "Runtime config changes not yet persisted"}


@app.post("/api/scan/start")
async def scan_start(payload: dict, request: Request):
    """Launch nexus live in a background subprocess for the given target."""
    _require_token(request)
    global _active_scan
    target = payload.get("target", "127.0.0.1")

    if _active_scan["process"] and _active_scan["process"].poll() is None:
        return {"status": "already_running", "target": _active_scan["target"]}

    import sys as _sys

    # Notify clients that a scan is starting
    _active_scan = {"process": None, "target": target, "status": "starting"}
    await _broadcast_scan_event({"type": "phase", "target": target, "phase": 0, "message": "Scan starting…"})

    cmd = [_sys.executable, "-m", "nexus", "live", "--target", target]
    proc = _subprocess.Popen(
        cmd,
        stdout=_subprocess.PIPE,
        stderr=_subprocess.STDOUT,
        text=True,
        env={**__import__("os").environ, "NEXUS_LEGAL_ACK": "I_HAVE_WRITTEN_AUTHORIZATION"},
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