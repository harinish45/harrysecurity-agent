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

from nexus.foundation.guardrails import InputGuard, LegalGuard, ScopeGuard
from nexus.reporting.professional import ReportBranding, render_pdf
from nexus.runtime.telemetry import telemetry_store
from web.mission_api import router as mission_router

app = FastAPI(title="NEXUS-STRIKE Dashboard")
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.include_router(mission_router)

DASHBOARD_TOKEN = os.environ.get("NEXUS_DASHBOARD_TOKEN", "").strip()
_subprocess = subprocess
_active_scan = {"process": None, "target": None, "status": "idle"}
_ws_clients: set[WebSocket] = set()
_ws_loop: asyncio.AbstractEventLoop | None = None


def _require_token(request: Request):
    if DASHBOARD_TOKEN and request.headers.get("Authorization", "") != f"Bearer {DASHBOARD_TOKEN}":
        raise HTTPException(status_code=401, detail="Missing or invalid dashboard token")


def _normalize_finding(item):
    if isinstance(item, dict):
        severity = str(item.get("severity", "info")).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"
        return {**item, "severity": severity}
    return {"title": str(item)[:200], "severity": "info", "description": str(item)}


def _latest_report_json() -> Path | None:
    files = sorted(
        [p for p in REPORTS_DIR.glob("*.json") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ) if REPORTS_DIR.exists() else []
    return files[0] if files else None


def _report_path(filename: str) -> Path:
    candidate = (REPORTS_DIR / filename).resolve()
    reports_root = REPORTS_DIR.resolve()
    if candidate.parent != reports_root or candidate.suffix not in {".pdf", ".json"}:
        raise HTTPException(status_code=400, detail="Invalid report filename")
    return candidate


def _professional_report_path() -> Path:
    source = _latest_report_json()
    if source is None:
        raise HTTPException(status_code=404, detail="No assessment JSON report is available")
    output = REPORTS_DIR / "professional-latest.pdf"
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        branding = ReportBranding(
            organization_name=os.environ.get("NEXUS_REPORT_ORG", "Security Assessment"),
            report_title=os.environ.get("NEXUS_REPORT_TITLE", "Security Assessment Report"),
            classification=os.environ.get("NEXUS_REPORT_CLASSIFICATION", "CONFIDENTIAL"),
            logo_text=os.environ.get("NEXUS_REPORT_LOGO_TEXT", "NEXUS-STRIKE"),
            accent=os.environ.get("NEXUS_REPORT_ACCENT", "#2463a6"),
            footer=os.environ.get("NEXUS_REPORT_FOOTER", "Prepared by NEXUS-STRIKE"),
        )
        render_pdf(data, output, branding)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Professional report generation failed: {exc}") from exc
    return output


@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>NEXUS-STRIKE Dashboard</h1><p>Templates not found.</p>")


@app.get("/console", response_class=HTMLResponse)
async def professional_console():
    html_path = STATIC_DIR / "pro-console.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    raise HTTPException(status_code=404, detail="Professional console not found")


@app.get("/reports/pro")
async def professional_report(request: Request):
    _require_token(request)
    return FileResponse(_professional_report_path(), media_type="application/pdf", filename="NEXUS-STRIKE-Professional-Report.pdf")


@app.get("/api/reports")
async def get_reports(request: Request):
    _require_token(request)
    reports = []
    if REPORTS_DIR.exists():
        for file_path in REPORTS_DIR.iterdir():
            if file_path.is_file() and file_path.suffix in {".pdf", ".json"}:
                reports.append({"name": file_path.name, "size": file_path.stat().st_size,
                                "modified": file_path.stat().st_mtime,
                                "url": f"/api/reports/{file_path.name}"})
    return {"reports": sorted(reports, key=lambda item: item["modified"], reverse=True)}


@app.get("/api/reports/{filename}")
async def get_report(filename: str, request: Request):
    _require_token(request)
    file_path = _report_path(filename)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    media_type = "application/pdf" if file_path.suffix == ".pdf" else "application/json"
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


@app.get("/api/telemetry/summary")
async def get_telemetry_summary(request: Request):
    _require_token(request)
    metrics = telemetry_store.snapshot()
    total = len(metrics)
    completed = sum(item.status == "completed" for item in metrics)
    failed = sum(item.status == "failed" for item in metrics)
    average = sum(item.execution_seconds for item in metrics) / total * 1000 if metrics else 0.0
    return {
        "records": total,
        "completed": completed,
        "failed": failed,
        "success_rate": completed / total if total else 0.0,
        "average_execution_ms": round(average, 2),
        "evidence": sum(item.evidence_count for item in metrics),
        "findings": sum(item.finding_count for item in metrics),
    }


@app.get("/api/tools/profiles")
async def get_tool_profiles(request: Request):
    _require_token(request)
    from nexus.tools.registry import tool_registry
    return {"tools": tool_registry.list_profiles(), "count": tool_registry.count}


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
    from nexus.tools.registry import get_tool_count_by_domain, get_tool_domains
    counts = get_tool_count_by_domain()
    return {"domains": get_tool_domains(), "counts": counts, "total": sum(counts.values())}


async def _broadcast_scan_event(event: dict):
    stale = []
    for websocket in list(_ws_clients):
        try:
            await websocket.send_json(event)
        except Exception:
            stale.append(websocket)
    for websocket in stale:
        _ws_clients.discard(websocket)


def _broadcast_from_worker(event: dict):
    if _ws_loop and _ws_loop.is_running():
        asyncio.run_coroutine_threadsafe(_broadcast_scan_event(event), _ws_loop)


def _websocket_auth_check(websocket: WebSocket, params: dict | None = None) -> bool:
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
    await websocket.accept()
    _ws_loop = asyncio.get_running_loop()
    _ws_clients.add(websocket)
    try:
        process = _active_scan.get("process")
        running = process is not None and process.poll() is None
        await websocket.send_json({"type": "status", "status": "running" if running else _active_scan.get("status", "idle"),
                                   "target": _active_scan.get("target")})
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)


@app.websocket("/ws/steer")
async def websocket_steer(websocket: WebSocket):
    if not _websocket_auth_check(websocket):
        await websocket.close(code=4401, reason="Unauthorized")
        return
    await websocket.accept()
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass


@app.get("/api/findings")
async def get_findings(request: Request, limit: int = 50):
    _require_token(request)
    if not 1 <= limit <= 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    json_files = sorted([p for p in REPORTS_DIR.glob("*.json") if p.is_file()],
                        key=lambda p: p.stat().st_mtime, reverse=True) if REPORTS_DIR.exists() else []
    if not json_files:
        return {"findings": [], "total": 0, "target": None}
    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    findings = [_normalize_finding(f) for f in data.get("findings", [])]
    return {"findings": findings[:limit], "total": len(findings),
            "target": data.get("_meta", {}).get("target"), "report": json_files[0].name}


@app.get("/api/config")
async def get_config(request: Request):
    _require_token(request)
    from nexus.foundation.config import config
    return {"ollama_base_url": getattr(config, "ollama_base_url", "http://localhost:11434/v1"),
            "ollama_model": getattr(config, "ollama_model", "qwen2.5-coder:7b"), "reports_dir": str(REPORTS_DIR)}


@app.post("/api/config")
async def update_config(payload: dict, request: Request):
    _require_token(request)
    raise HTTPException(status_code=501, detail="Runtime config persistence is not implemented")


@app.post("/api/scan/start")
async def scan_start(payload: dict, request: Request):
    _require_token(request)
    target = payload.get("target", "127.0.0.1")
    if not isinstance(target, str) or not target.strip():
        raise HTTPException(status_code=400, detail="target must be a non-empty string")
    try:
        InputGuard.validate(target, context={"source": "dashboard"})
        ScopeGuard.validate(target)
        LegalGuard.validate(target=target)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Scan blocked by guardrail: {exc}") from exc
    process = _active_scan.get("process")
    if process and process.poll() is None:
        return {"status": "already_running", "target": _active_scan["target"]}
    _active_scan.update({"process": None, "target": target, "status": "starting"})
    await _broadcast_scan_event({"type": "phase", "target": target, "phase": 0, "message": "Scan starting"})
    proc = _subprocess.Popen([os.sys.executable, "-m", "nexus", "live", "--target", target],
                             stdout=_subprocess.PIPE, stderr=_subprocess.STDOUT, text=True, env=dict(os.environ))
    _active_scan.update({"process": proc, "status": "running"})
    await _broadcast_scan_event({"type": "status", "status": "running", "target": target})

    def _stream_output(process):
        if process.stdout is None:
            return
        for line in process.stdout:
            line = line.rstrip()
            if line:
                _broadcast_from_worker({"type": "output", "target": target, "line": line})
        _broadcast_from_worker({"type": "status", "status": "completed", "target": target})

    threading.Thread(target=_stream_output, args=(proc,), daemon=True).start()
    return {"status": "started", "target": target, "pid": proc.pid}


@app.post("/api/scan/stop")
async def scan_stop(request: Request):
    _require_token(request)
    process = _active_scan.get("process")
    if process and process.poll() is None:
        process.terminate()
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


def _open_browser_safe(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        print(f"[nexus] Browser could not be opened automatically. Visit {url} manually.")


def launch_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    url = f"http://{host}:{port}"
    if open_browser:
        threading.Timer(1.5, lambda: _open_browser_safe(url)).start()
    print(f"[nexus] Dashboard available at: {url}")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    launch_dashboard()
