from fastapi.testclient import TestClient

from nexus.mission import MissionService, MissionStore
from web import mission_api
from web.server import app


def test_mission_api_create_list_and_replay(tmp_path, monkeypatch):
    mission_api._service = MissionService(MissionStore(tmp_path))
    monkeypatch.delenv("NEXUS_DASHBOARD_TOKEN", raising=False)
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
