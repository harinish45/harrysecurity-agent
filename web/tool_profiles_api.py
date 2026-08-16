"""Read-only tool capability/performance catalogue API and dashboard page."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from nexus.tools.registry import tool_registry

router = APIRouter(tags=["tools"])
STATIC_DIR = Path(__file__).parent / "static"


@router.get("/api/tools/profiles")
def list_tool_profiles() -> dict[str, object]:
    """Return JSON-safe tool execution profiles for the dashboard."""
    return {"tools": tool_registry.list_profiles(), "count": tool_registry.count}


@router.get("/tools/performance", include_in_schema=False)
def tool_performance_page() -> FileResponse:
    """Serve the operator-facing performance catalogue."""
    return FileResponse(STATIC_DIR / "tool-performance.html", media_type="text/html")
