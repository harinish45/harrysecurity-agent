from nexus.mission.models import Mission, MissionStatus, MissionStore


def test_mission_lifecycle_and_events(tmp_path):
    mission = Mission("m-001", "127.0.0.1")

    mission.transition(MissionStatus.AUTHORIZED, actor="operator", reason="written authorization")
    mission.transition(MissionStatus.PLANNING)
    mission.transition(MissionStatus.QUEUED)
    mission.transition(MissionStatus.RUNNING)
    mission.record("tool.started", payload={"tool": "network.port_scan"})
    mission.transition(MissionStatus.COMPLETED)

    assert mission.status is MissionStatus.COMPLETED
    assert len(mission.events) == 6
    assert mission.events[-1].payload["to"] == "completed"


def test_invalid_transition_is_rejected():
    mission = Mission("m-002", "127.0.0.1")

    try:
        mission.transition(MissionStatus.RUNNING)
    except ValueError as exc:
        assert "Invalid mission transition" in str(exc)
    else:
        raise AssertionError("invalid mission transition was accepted")


def test_mission_store_round_trip(tmp_path):
    store = MissionStore(tmp_path)
    mission = Mission("m-003", "localhost")
    mission.transition(MissionStatus.AUTHORIZED)
    mission.record("mission.scope_verified", payload={"scope": ["localhost"]})
    store.save(mission)

    loaded = store.load("m-003")
    assert loaded.mission_id == mission.mission_id
    assert loaded.target == "localhost"
    assert loaded.status is MissionStatus.AUTHORIZED
    assert loaded.events[0].type == "mission.status_changed"
    assert loaded.events[1].type == "mission.scope_verified"


def test_store_ignores_corrupt_files(tmp_path):
    store = MissionStore(tmp_path)
    (tmp_path / "broken.json").write_text("not-json", encoding="utf-8")
    assert store.list() == []
