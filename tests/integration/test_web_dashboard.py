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


# ── Hardening regression tests ──────────────────────────────────────────

def test_security_headers_present(client):
    """Every response must carry the security headers middleware's headers."""
    response = client.get("/")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in response.headers


def test_report_path_traversal_rejected(client):
    """A traversal attempt must never escape REPORTS_DIR — same 404 as a
    plain missing file, not a 500 or (worse) file contents."""
    response = client.get("/api/reports/..%5c..%5c..%5cWindows%5cwin.ini")
    assert response.status_code == 404
    assert "detail" in response.json()


def test_scan_post_requires_csrf_header(client):
    """State-changing POSTs must reject requests missing the same-origin
    signal header, regardless of dashboard-token state."""
    response = client.post("/api/scan/stop")
    assert response.status_code == 403
    assert "X-Requested-With" in response.json()["detail"]


def test_scan_post_with_csrf_header_passes_the_gate(client):
    """With the header present, the request proceeds past the CSRF check
    (it may still no-op if there's no active scan — that's fine, the point
    here is it's not rejected at 403)."""
    response = client.post("/api/scan/stop", headers={"X-Requested-With": "NEXUS-Dashboard"})
    assert response.status_code != 403


def test_scan_start_requires_legal_ack(client, monkeypatch):
    """/api/scan/start must not auto-inject NEXUS_LEGAL_ACK — it has to
    already be set in the server's environment."""
    monkeypatch.delenv("NEXUS_LEGAL_ACK", raising=False)
    response = client.post(
        "/api/scan/start",
        json={"target": "127.0.0.1"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 403
    assert "NEXUS_LEGAL_ACK" in response.json()["detail"]


def test_scan_start_rejects_out_of_scope_target(client, monkeypatch):
    """/api/scan/start must validate the target through ScopeGuard before
    spawning anything, not rely solely on the subprocess's own executor
    chain to reject it after the fact."""
    monkeypatch.setenv("NEXUS_LEGAL_ACK", "I_HAVE_WRITTEN_AUTHORIZATION")
    response = client.post(
        "/api/scan/start",
        json={"target": "definitely-not-an-allowed-target.invalid"},
        headers={"X-Requested-With": "NEXUS-Dashboard"},
    )
    assert response.status_code == 400


def test_production_mode_requires_dashboard_token():
    """NEXUS_ENV=production with no NEXUS_DASHBOARD_TOKEN must refuse to
    start the server at all (a fresh interpreter is required since
    web.server does this check at import time)."""
    import subprocess
    import sys
    import os as _os

    env = dict(_os.environ)
    env["NEXUS_ENV"] = "production"
    env.pop("NEXUS_DASHBOARD_TOKEN", None)
    result = subprocess.run(
        [sys.executable, "-c", "import web.server"],
        cwd=_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "NEXUS_DASHBOARD_TOKEN" in result.stderr


def test_ws_steer_requires_token_when_configured():
    """/ws/steer used to have zero auth even when /ws/scan required a
    token. Both must now enforce the same check."""
    import os as _os
    import subprocess
    import sys

    env = dict(_os.environ)
    env["NEXUS_DASHBOARD_TOKEN"] = "test-token-for-ws-steer-check"
    script = (
        "import web.server as srv\n"
        "from fastapi.testclient import TestClient\n"
        "c = TestClient(srv.app)\n"
        "try:\n"
        "    with c.websocket_connect('/ws/steer'):\n"
        "        raise SystemExit(1)\n"
        "except Exception:\n"
        "    raise SystemExit(0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
