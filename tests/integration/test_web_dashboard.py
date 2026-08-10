"""
Integration tests for the NEXUS-STRIKE Strix web dashboard.
Tests cover server startup, API endpoints, and skill/agent/tool data APIs.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a test client for the dashboard FastAPI app."""
    from web.server import app
    return TestClient(app)


def test_dashboard_root_returns_html(client):
    """GET / should return the dashboard HTML page."""
    response = client.get("/")
    assert response.status_code == 200
    # Either the full HTML or the fallback message
    assert "NEXUS-STRIKE" in response.text


def test_api_reports_endpoint(client):
    """GET /api/reports should return a JSON object with a reports list."""
    response = client.get("/api/reports")
    assert response.status_code == 200
    data = response.json()
    assert "reports" in data
    assert isinstance(data["reports"], list)


def test_api_stats_endpoint(client):
    """GET /api/stats should return stats or a no-reports error gracefully."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    # Either has findings data or graceful error
    assert "error" in data or "total_findings" in data


def test_api_agents_endpoint(client):
    """GET /api/agents should return agent tier data."""
    response = client.get("/api/agents")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "by_tier" in data
    assert data["total"] > 0
    assert "orchestrator" in data["by_tier"]


def test_api_skills_endpoint(client):
    """GET /api/skills should return skill registry data."""
    response = client.get("/api/skills")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert data["total"] == 7  # 7 domain skills registered


def test_api_tools_endpoint(client):
    """GET /api/tools should return tool domain groupings."""
    response = client.get("/api/tools")
    assert response.status_code == 200
    data = response.json()
    assert "domains" in data
    assert "total" in data
    assert data["total"] > 0
    assert len(data["domains"]) >= 20  # 29 domains expected


def test_api_report_not_found(client):
    """GET /api/reports/nonexistent.pdf should return 404."""
    response = client.get("/api/reports/nonexistent_file_12345.pdf")
    assert response.status_code == 404


def test_launch_dashboard_importable():
    """launch_dashboard function must be importable from web.server."""
    from web.server import launch_dashboard
    import inspect
    sig = inspect.signature(launch_dashboard)
    assert "host" in sig.parameters
    assert "port" in sig.parameters
    assert "open_browser" in sig.parameters
