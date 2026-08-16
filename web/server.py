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
from web.tool_profiles_api import router as tool_profiles_router

app = FastAPI(title="NEXUS-STRIKE Dashboard")
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.include_router(tool_profiles_router)

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


def _report_path(filename: str) -> Path:
    candidate = (REPORTS_DIR / filename).resolve()
    reports_root = REPORTS_DIR.resolve()
    if candidate.parent != reports_root or candidate.suffix not in {".pdf", ".json"}:
        raise HTTPException(status_code=400, detail="Invalid report filename")
    return candidate


@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>NEXUS-STRIKE Dashboard</h1><p>Templates not found.</p>")


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
