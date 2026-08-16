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

from nexus.foundation.guardrails import InputGuard, ScopeGuard, LegalGuard

app = FastAPI(title="NEXUS-STRIKE Dashboard")

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

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
                    "url": f"/api/reports/{f.name}",
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
    if filename.endswith(".json"):
        return FileResponse(file_path, media_type="application/json")
    raise HTTPException(status_code=400, detail="Unsupported file type")


@app.get("/api/stats")
async def get_stats(request: Request):
    """Get dashboard statistics from latest report."""
    _require_token(request)
    latest_json = None
    if REPORTS_DIR.exists():
        json_files = sorted(
            [f for f in REPORTS_DIR.iterdir() if f.suffix == ".json"],
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )
        if json_files:
            latest_json = json_files[0]

    if latest_json:
        with open(latest_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = data.get("findings", [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = _normalize_finding(finding).get("severity", "info")
            severity_counts[sev if sev in severity_counts else "info"] += 1
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
        return {"total": get_agent_count(), "by_tier": get_agents_by_tier()}
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
        counts = get_tool_count_by_domain()
        return {"domains": get_tool_domains(), "counts": counts, "total": sum(counts.values())}
    except ImportError:
        return {"domains": [], "counts": {}, "total": 0}


import subprocess as _subprocess
_active_scan: dict = {"process": None, "target": None, "status": "idle"}
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
    return websocket.headers.get("Authorization", "") == f"Bearer {DASHBOARD_TOKEN}"


@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    """WebSocket endpoint for real-time scan progress streaming."""
    if not _websocket_auth_check(websocket, dict(websocket.query_params)):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        proc = _active_scan.get("process")
        running = proc is not None and proc.poll() is None
        await websocket.send_json({
            "type": "status",
            "status": "running" if running else _active_scan.get("status", "idle"),
            "target": _active_scan.get("target"),
        })
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "ack", "message": data})
    except Exception:
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


@app.websocket("/ws/steer")
async def websocket_steer(websocket: WebSocket):
    """Authenticated WebSocket endpoint for future live scan steering."""
    if not _websocket_auth_check(websocket, dict(websocket.query_params)):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Acknowledged: {data}")
    except Exception:
        pass


@app.get("/api/findings")
async def get_findings(request: Request, limit: int = 50):
    """Return findings from the most recent JSON report."""
    _require_token(request)
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
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
    findings = [_normalize_finding(f) for f in data.get("findings", [])]
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
            "ollama_model": getattr(config, "ollama_model", "qwen2.5-coder:7b"),
            "reports_dir": str(REPORTS_DIR),
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
    """Launch a guarded nexus live scan in a background subprocess."""
    _require_token(request)
    global _active_scan
    target = payload.get("target", "127.0.0.1")
    if not isinstance(target, str) or not target.strip():
        raise HTTPException(status_code=400, detail="target must be a non-empty string")

    # Enforce the same controls at the dashboard boundary before process creation.
    try:
        InputGuard.validate(target, context={"source": "dashboard"})
        ScopeGuard.validate(target)
        LegalGuard.validate(target=target)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Scan blocked by guardrail: {exc}") from exc

    proc = _active_scan.get("process")
    if proc and proc.poll() is None:
        return {"status": "already_running", "target": _active_scan["target"]}

    import sys as _sys
    _active_scan = {"process": None, "target": target, "status": "starting"}
    await _broadcast_scan_event({"type": "phase", "target": target, "phase": 0, "message": "Scan starting…"})

    cmd = [_sys.executable, "-m", "nexus", "live", "--target", target]
    proc = _subprocess.Popen(
        cmd,
        stdout=_subprocess.PIPE,
        stderr=_subprocess.STDOUT,
        text=True,
        env=dict(os.environ),
    )
    _active_scan = {"process": proc, "target": target, "status": "running"}
    await _broadcast_scan_event({"type": "status", "status": "running", "target": target})

    import threading

    def _stream_output(process):
        if process.stdout is None:
            return
        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(_broadcast_scan_event({"type": "output", "target": target, "line": line}))
                finally:
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
        print(f"[nexus] Browser could not be opened automatically. Visit {url} manually.")


def launch_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Launch the dashboard and optionally open the browser."""
    url = f"http://{host}:{port}"
    if open_browser:
        import threading
        threading.Timer(1.5, lambda: _open_browser_safe(url)).start()
    print(f"[nexus] Dashboard available at: {url}")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    launch_dashboard()
