"""Read-only tool capability/performance catalogue API."""
from __future__ import annotations

from fastapi import APIRouter

from nexus.tools.registry import tool_registry

router = APIRouter(prefix="/api/tools", tags=["tools"])


@router.get("/profiles")
def list_tool_profiles() -> dict[str, object]:
    """Return JSON-safe tool execution profiles for the dashboard."""
    return {"tools": tool_registry.list_profiles(), "count": tool_registry.count}
