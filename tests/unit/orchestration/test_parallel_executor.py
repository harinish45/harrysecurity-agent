import time

import pytest

from nexus.orchestration.scheduler.parallel_executor import ParallelExecutor
from nexus.orchestration.scheduler.resource_allocator import ResourceAllocator


@pytest.mark.asyncio
async def test_independent_jobs_actually_run_concurrently():
    """The whole point of ParallelExecutor: N blocking jobs that each take
    ~0.3s must complete in ~0.3s total, not N * 0.3s — proving the batch
    genuinely overlaps on the thread pool rather than serializing."""
    allocator = ResourceAllocator(max_workers=4)
    executor = ParallelExecutor(allocator)

    def _slow_job():
        time.sleep(0.3)
        return "done"

    jobs = {f"job-{i}": _slow_job for i in range(4)}

    started = time.monotonic()
    results = await executor.run_batch(jobs)
    elapsed = time.monotonic() - started

    assert all(r.ok and r.value == "done" for r in results.values())
    # Serial execution would take >= 1.2s; concurrent execution should land
    # comfortably under 1s even with scheduling overhead.
    assert elapsed < 1.0, f"jobs did not run concurrently (took {elapsed:.2f}s)"

    allocator.shutdown()


@pytest.mark.asyncio
async def test_one_job_failing_does_not_abort_the_batch():
    allocator = ResourceAllocator(max_workers=2)
    executor = ParallelExecutor(allocator)

    def _ok():
        return "fine"

    def _boom():
        raise RuntimeError("kaboom")

    results = await executor.run_batch({"good": _ok, "bad": _boom})

    assert results["good"].ok is True
    assert results["good"].value == "fine"
    assert results["bad"].ok is False
    assert "kaboom" in results["bad"].error

    allocator.shutdown()


@pytest.mark.asyncio
async def test_empty_batch_returns_empty_results():
    executor = ParallelExecutor(ResourceAllocator(max_workers=1))
    assert await executor.run_batch({}) == {}
