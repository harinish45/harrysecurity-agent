import os

from fastapi.testclient import TestClient

from web.server import app


def test_mission_api_create_list_and_replay(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_MISSIONS_DIR", str(tmp_path))
    # Importing a fresh process would normally create the configured singleton;
    # this endpoint contract test focuses on routing and serialization.
    client = TestClient(app)

    response = client.post(
        "/api/missions",
        json={"target": "127.0.0.1", "authorization_reference": "TEST-AUTH"},
    )
    assert response.status_code == 200
    mission = response.json()
    assert mission["target"] == "127.0.0.1"
    assert mission["status"] == "created"

    mission_id = mission["mission_id"]
    fetched = client.get(f"/api/missions/{mission_id}")
    assert fetched.status_code == 200
    assert fetched.json()["mission"]["mission_id"] == mission_id

    events = client.get(f"/api/missions/{mission_id}/events")
    assert events.status_code == 200
    assert events.json()["events"][0]["event_type"] == "mission.created"
