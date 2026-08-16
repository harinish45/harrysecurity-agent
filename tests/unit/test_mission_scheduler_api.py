from fastapi.testclient import TestClient

from web.server import app
from web.mission_api import _service


def test_mission_job_submission_is_scope_checked_and_listed(monkeypatch, tmp_path):
    monkeypatch.delenv("NEXUS_DASHBOARD_TOKEN", raising=False)
    _service.store.root = tmp_path
    client = TestClient(app)
    created = client.post("/api/missions", json={"target": "127.0.0.1", "authorization_reference": "TEST-AUTH"})
    assert created.status_code == 200
    mission_id = created.json()["mission_id"]
    assert client.post(f"/api/missions/{mission_id}/transition", json={"status": "authorized"}).status_code == 200
    queued = client.post(f"/api/missions/{mission_id}/jobs", json={"capability": "network.port_discovery", "target_scope": ["127.0.0.1"]})
    assert queued.status_code == 200
    assert queued.json()["state"] == "queued"
    listing = client.get(f"/api/missions/{mission_id}/jobs")
    assert listing.status_code == 200
    assert listing.json()["jobs"][0]["capability"] == "network.port_discovery"


def test_mission_job_rejects_scope_outside_mission(monkeypatch, tmp_path):
    monkeypatch.delenv("NEXUS_DASHBOARD_TOKEN", raising=False)
    _service.store.root = tmp_path
    client = TestClient(app)
    created = client.post("/api/missions", json={"target": "127.0.0.1", "authorization_reference": "TEST-AUTH"})
    mission_id = created.json()["mission_id"]
    client.post(f"/api/missions/{mission_id}/transition", json={"status": "authorized"})
    rejected = client.post(f"/api/missions/{mission_id}/jobs", json={"capability": "network.port_discovery", "target_scope": ["127.0.0.2"]})
    assert rejected.status_code in {403, 409}
