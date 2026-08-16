from nexus.agents.capabilities import RiskLevel
from nexus.runtime.events import Event, EventBus
from nexus.runtime.workers import WorkerJob, WorkerState


def test_event_bus_assigns_monotonic_sequence_and_replays_by_mission():
    bus = EventBus()
    first = bus.publish(Event("e1", "m1", "mission.created", "t1", {}))
    second = bus.publish(Event("e2", "m2", "mission.created", "t2", {}))
    assert (first.sequence, second.sequence) == (1, 2)
    assert [event.event_id for event in bus.replay(mission_id="m1")] == ["e1"]
    assert [event.event_id for event in bus.replay(after_sequence=1)] == ["e2"]


def test_event_subscriber_failure_does_not_break_publish():
    bus = EventBus()
    bus.subscribe(lambda event: (_ for _ in ()).throw(RuntimeError("observer failed")))
    committed = bus.publish(Event("e1", "m1", "finding.created", "t1", {"id": "f1"}))
    assert committed.sequence == 1


def test_worker_job_requires_explicit_scope():
    job = WorkerJob("j1", "m1", "t1", "web-recon", (), RiskLevel.LOW)
    try:
        job.validate()
    except ValueError as exc:
        assert "scope" in str(exc)
    else:
        raise AssertionError("expected explicit scope validation")


def test_worker_job_accepts_authorized_scope():
    job = WorkerJob("j1", "m1", "t1", "web-recon", ("example.test",))
    job.validate()
    assert job.attempt == 1
    assert WorkerState.QUEUED.value == "queued"
