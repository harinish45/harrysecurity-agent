from nexus.tools.execution import ExecutionStatus, FunctionToolAdapter, ToolExecutionContext, ToolOutcome
from nexus.tools.limits import ToolLimiter
from nexus.tools.profile import ToolProfile


def context():
    return ToolExecutionContext("mission-1", "job-1", ("127.0.0.1",), 30)


def test_function_adapter_normalizes_success_and_failure():
    profile = ToolProfile(name="test.echo", domain="test", max_concurrency=1)
    adapter = FunctionToolAdapter("test.echo", profile, lambda **kwargs: {"output": "ok"})
    result = adapter.execute(context(), {})
    assert result.status is ExecutionStatus.COMPLETED
    assert result.output == {"output": "ok"}
    assert result.duration_seconds >= 0

    failing = FunctionToolAdapter("test.fail", profile, lambda **kwargs: (_ for _ in ()).throw(ValueError("bad")))
    failed = failing.execute(context(), {})
    assert failed.status is ExecutionStatus.FAILED
    assert failed.error_class == "ValueError"


def test_limiter_enforces_concurrency_and_releases():
    profile = ToolProfile(name="test.rate", domain="test", max_concurrency=1)
    limiter = ToolLimiter()
    assert limiter.acquire(profile).allowed
    blocked = limiter.acquire(profile)
    assert not blocked.allowed
    limiter.release(profile)
    assert limiter.acquire(profile).allowed
    limiter.release(profile)


def test_outcome_is_immutable():
    outcome = ToolOutcome(ExecutionStatus.COMPLETED, 1.0, 2.0)
    assert outcome.duration_seconds == 1.0
    try:
        outcome.status = ExecutionStatus.FAILED
    except AttributeError:
        pass
    else:
        raise AssertionError("ToolOutcome must be immutable")
