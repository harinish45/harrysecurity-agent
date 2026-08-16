from fastapi.testclient import TestClient

from web.server import app


def test_tool_profile_api_and_page_are_mounted(monkeypatch):
    monkeypatch.delenv("NEXUS_DASHBOARD_TOKEN", raising=False)
    client = TestClient(app)

    response = client.get("/api/tools/profiles")
    assert response.status_code == 200
    payload = response.json()
    assert "tools" in payload
    assert "count" in payload
    assert payload["count"] >= 1

    page = client.get("/tools/performance")
    assert page.status_code == 200
    assert "Tool Performance Fabric" in page.text
