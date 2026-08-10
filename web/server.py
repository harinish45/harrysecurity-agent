#!/usr/bin/env python3
"""
NEXUS-STRIKE Web Dashboard Server
Strix-style local security platform interface.
"""
import os
import json
import uvicorn
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

app = FastAPI(title="NEXUS-STRIKE Dashboard")

# Mount static files
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return HTMLResponse("<h1>NEXUS-STRIKE Dashboard</h1><p>Templates not found.</p>")

@app.get("/api/reports")
async def get_reports():
    """List all available PDF and JSON reports."""
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
async def get_report(filename: str):
    """Serve a specific report file."""
    file_path = REPORTS_DIR / filename
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    
    if filename.endswith(".pdf"):
        return FileResponse(file_path, media_type="application/pdf")
    elif filename.endswith(".json"):
        return FileResponse(file_path, media_type="application/json")
    raise HTTPException(status_code=400, detail="Unsupported file type")

@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics from latest report."""
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
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        return {
            "target": data.get("_meta", {}).get("target", "Unknown"),
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "open_ports": data.get("open_ports", []),
            "phases_completed": data.get("_meta", {}).get("phases_completed", 0)
        }
    return {"error": "No reports found"}

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

@app.get("/api/agents")
async def get_agents():
    """Get all agents grouped by tier for topology view."""
    try:
        from nexus.agents.agent_registry import get_agents_by_tier, get_agent_count
        return {
            "total": get_agent_count(),
            "by_tier": get_agents_by_tier(),
        }
    except ImportError:
        return {"total": 0, "by_tier": {}}


@app.get("/api/skills")
async def get_skills():
    """Get all registered skills from both registries."""
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
async def get_tools():
    """Get tool counts grouped by domain."""
    try:
        from nexus.tools.registry import get_tool_count_by_domain, get_tool_domains
        return {
            "domains": get_tool_domains(),
            "counts": get_tool_count_by_domain(),
            "total": sum(get_tool_count_by_domain().values()),
        }
    except ImportError:
        return {"domains": [], "counts": {}, "total": 0}


def launch_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Launch the Strix dashboard and optionally open the browser."""
    if open_browser:
        import threading
        import webbrowser
        url = f"http://{host}:{port}"
        # Open browser after a short delay so the server is ready
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    launch_dashboard()