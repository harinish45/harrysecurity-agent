import pytest

from nexus.agents.capabilities import RiskLevel
from nexus.runtime.scheduler import JobScheduler, JobState
from nexus.runtime.workers import WorkerJob


def make_job(job_id: str = "job-1") -> WorkerJob:
    return WorkerJob(
        job_id=job_id,
        mission_id="mission-1",
        task_id="task-1",
        capability="utility.echo",
        target_scope=("127.0.0.1",),
        risk_level=RiskLevel.LOW,
        timeout_seconds=10,
    )


def test_scheduler_claims_priority_order_and_tracks_state():
    scheduler = JobScheduler(max_pending=2)
    scheduler.submit(make_job("low"), priority=100)
    scheduler.submit(make_job("high"), priority=10)

    claimed = scheduler.claim()
    assert claimed is not None
    assert claimed.job.job_id == "high"
    assert claimed.state is JobState.RUNNING

    scheduler.complete("high")
    assert scheduler.get("high").state is JobState.COMPLETED


def test_scheduler_cancels_queued_job_without_claiming_it():
    scheduler = JobScheduler()
    scheduler.submit(make_job())

    cancelled = scheduler.cancel("job-1")
    assert cancelled.state is JobState.CANCELLED
    assert scheduler.claim() is None


def test_scheduler_retries_failed_job_with_incremented_attempt():
    scheduler = JobScheduler()
    scheduler.submit(make_job())
    scheduler.claim()
    scheduler.fail("job-1", error="network")

    retried = scheduler.retry("job-1")
    assert retried.state is JobState.QUEUED
    assert retried.retries == 1
    assert retried.job.attempt == 2


def test_scheduler_enforces_pending_bound():
    scheduler = JobScheduler(max_pending=1)
    scheduler.submit(make_job())
    with pytest.raises(RuntimeError, match="queue is full"):
        scheduler.submit(make_job("job-2"))


def test_scheduler_rejects_duplicate_job_ids():
    scheduler = JobScheduler()
    scheduler.submit(make_job())
    with pytest.raises(ValueError, match="duplicate job id"):
        scheduler.submit(make_job())
