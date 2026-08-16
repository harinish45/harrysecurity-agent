from nexus.mission.models import MissionStatus, MissionStore
from nexus.mission.service import MissionService
from nexus.runtime.events import EventBus


def test_service_persists_transitions_and_replays_events(tmp_path):
    service = MissionService(MissionStore(tmp_path), EventBus())
    mission = service.create("127.0.0.1", authorization_reference="AUTH-1")

    service.transition(mission.mission_id, MissionStatus.AUTHORIZED)
    service.transition(mission.mission_id, MissionStatus.PLANNING)

    restored = service.get(mission.mission_id)
    assert restored.status is MissionStatus.PLANNING
    events = service.replay(mission.mission_id)
    assert [event.event_type for event in events] == [
        "mission.created",
        "mission.status_changed",
        "mission.status_changed",
    ]
    assert [event.sequence for event in events] == [1, 2, 3]


def test_service_projection_does_not_include_metadata_or_events(tmp_path):
    service = MissionService(MissionStore(tmp_path), EventBus())
    mission = service.create("example.local", metadata={"internal": "secret"})

    projection = service.summarize(mission).to_dict()
    assert projection["target"] == "example.local"
    assert "metadata" not in projection
    assert "events" not in projection


def test_subscriber_failure_does_not_break_mission_creation(tmp_path):
    bus = EventBus()
    bus.subscribe(lambda _event: (_ for _ in ()).throw(RuntimeError("observer failure")))
    service = MissionService(MissionStore(tmp_path), bus)

    mission = service.create("localhost")
    assert service.get(mission.mission_id).status.value == "created"
