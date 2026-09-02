from fastapi.testclient import TestClient

from web.server import app


def test_professional_console_and_report_routes(monkeypatch):
    monkeypatch.delenv("NEXUS_DASHBOARD_TOKEN", raising=False)
    client = TestClient(app)

    console = client.get("/console")
    assert console.status_code == 200
    assert "NEXUS-STRIKE" in console.text
    assert "Command Center" in console.text

    telemetry = client.get("/api/telemetry/summary")
    assert telemetry.status_code == 200
    assert "success_rate" in telemetry.json()

    missions = client.get("/api/missions")
    assert missions.status_code == 200
