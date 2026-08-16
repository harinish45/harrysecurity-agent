import sys

from nexus.agents.capabilities import RiskLevel
from nexus.runtime.process.worker import LocalProcessWorker
from nexus.runtime.telemetry import TelemetryStore, telemetry_store
from nexus.runtime.workers import WorkerJob, WorkerState


def make_job(**overrides):
    data = {
        "job_id": "telemetry-job",
        "mission_id": "mission-1",
        "task_id": "task-1",
        "capability": "utility.echo",
        "target_scope": ("127.0.0.1",),
        "risk_level": RiskLevel.LOW,
    }
    data.update(overrides)
    return WorkerJob(**data)


def test_worker_emits_completed_metric():
    telemetry_store.clear()
    result = LocalProcessWorker().execute(make_job(), [sys.executable, "-c", "print('ok')"])
    assert result.state is WorkerState.COMPLETED
    metrics = telemetry_store.snapshot()
    assert len(metrics) == 1
    assert metrics[0].job_id == "telemetry-job"
    assert metrics[0].status == "completed"
    assert metrics[0].stdout_bytes > 0
    assert metrics[0].attempt == 1
    assert metrics[0].execution_seconds >= 0


def test_worker_emits_timeout_metric():
    telemetry_store.clear()
    result = LocalProcessWorker().execute(make_job(timeout_seconds=1), [sys.executable, "-c", "import time; time.sleep(2)"])
    assert result.state is WorkerState.FAILED
    metrics = telemetry_store.snapshot()
    assert metrics[0].error_class == "TimeoutExpired"


def test_telemetry_store_is_bounded_and_snapshot_is_immutable():
    store = TelemetryStore(max_items=2)
    base = dict(mission_id="m", job_id="j", tool_name="t", status="completed", started_at=1.0, finished_at=2.0)
    for index in range(3):
        store.record(__import__("nexus.runtime.telemetry", fromlist=["ToolExecutionMetric"]).ToolExecutionMetric(job_id=f"j{index}", **{k: v for k, v in base.items() if k != "job_id"}))
    snapshot = store.snapshot()
    assert [metric.job_id for metric in snapshot] == ["j1", "j2"]
    assert isinstance(snapshot, tuple)
