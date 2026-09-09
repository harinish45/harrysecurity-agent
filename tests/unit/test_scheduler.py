import pytest

from nexus.agents.capabilities import RiskLevel
from nexus.runtime.scheduler import JobScheduler, JobState
from nexus.runtime.workers import WorkerJob, WorkerResult, WorkerState


def job(job_id: str) -> WorkerJob:
    return WorkerJob(job_id, "mission-1", "task-1", "utility.echo", ("127.0.0.1",), RiskLevel.LOW, 10)


def test_priority_queue_and_lifecycle():
    scheduler = JobScheduler(max_pending=2)
    scheduler.submit(job("low"), priority=100)
    scheduler.submit(job("high"), priority=10)
    claimed = scheduler.claim()
    assert claimed.job.job_id == "high"
    assert claimed.state is JobState.RUNNING
    assert scheduler.complete("high").state is JobState.COMPLETED


def test_cancel_removes_queued_job_from_claims():
    scheduler = JobScheduler()
    scheduler.submit(job("cancel"))
    assert scheduler.cancel("cancel").state is JobState.CANCELLED
    assert scheduler.claim() is None


def test_failed_job_can_retry_with_incremented_attempt():
    scheduler = JobScheduler()
    scheduler.submit(job("retry"))
    scheduler.claim()
    scheduler.fail("retry", error="temporary")
    retried = scheduler.retry("retry")
    assert retried.job.attempt == 2
    assert retried.retries == 1
    assert retried.state is JobState.QUEUED


def test_dispatch_normalizes_worker_result():
    scheduler = JobScheduler()
    scheduler.submit(job("dispatch"))
    result = scheduler.dispatch(lambda _job: WorkerResult("dispatch", WorkerState.COMPLETED))
    assert result is not None
    assert result.state is JobState.COMPLETED


def test_dispatch_records_worker_failure():
    scheduler = JobScheduler()
    scheduler.submit(job("fail"))
    result = scheduler.dispatch(lambda _job: WorkerResult("fail", WorkerState.FAILED, error="tool failed"))
    assert result is not None
    assert result.state is JobState.FAILED
    assert result.error == "tool failed"


def test_queue_bound_and_duplicate_protection():
    scheduler = JobScheduler(max_pending=1)
    scheduler.submit(job("one"))
    with pytest.raises(ValueError, match="duplicate job id"):
        scheduler.submit(job("one"))
    with pytest.raises(RuntimeError, match="queue is full"):
        scheduler.submit(job("two"))
