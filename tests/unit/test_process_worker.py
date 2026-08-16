import sys

import pytest

from nexus.agents.capabilities import RiskLevel
from nexus.runtime.events import EventBus
from nexus.runtime.process.worker import LocalProcessWorker
from nexus.runtime.tool_metrics import ToolMetricsStore
from nexus.runtime.workers import WorkerJob, WorkerState


def make_job(**overrides):
    data = {
        "job_id": "job-1",
        "mission_id": "mission-1",
        "task_id": "task-1",
        "capability": "utility.echo",
        "target_scope": ("127.0.0.1",),
        "risk_level": RiskLevel.LOW,
    }
    data.update(overrides)
    return WorkerJob(**data)


def test_process_worker_executes_without_shell_and_emits_events():
    bus = EventBus()
    metrics = ToolMetricsStore()
    worker = LocalProcessWorker(bus, metrics)
    result = worker.execute(make_job(), [sys.executable, "-c", "print('ok')"])

    assert result.state is WorkerState.COMPLETED
    assert [event.event_type for event in bus.events] == ["worker.started", "worker.completed"]
    record = metrics.list()[0]
    assert record.status == "completed"
    assert record.execution_ms >= 0
    assert record.stdout_bytes > 0


def test_process_worker_rejects_nul_and_empty_argv():
    worker = LocalProcessWorker()
    with pytest.raises(ValueError):
        worker.execute(make_job(), [])
    with pytest.raises(ValueError):
        worker.execute(make_job(), ["python\x00"])


def test_process_worker_reports_nonzero_exit():
    metrics = ToolMetricsStore()
    worker = LocalProcessWorker(metrics_store=metrics)
    result = worker.execute(make_job(), [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(2)"])

    assert result.state is WorkerState.FAILED
    assert "boom" in result.error
    assert metrics.list()[0].error_class == "ProcessExit"


def test_process_worker_enforces_timeout():
    metrics = ToolMetricsStore()
    worker = LocalProcessWorker(metrics_store=metrics)
    result = worker.execute(make_job(timeout_seconds=1), [sys.executable, "-c", "import time; time.sleep(2)"])

    assert result.state is WorkerState.FAILED
    assert result.error == "worker timed out"
    assert metrics.list()[0].error_class == "TimeoutExpired"
