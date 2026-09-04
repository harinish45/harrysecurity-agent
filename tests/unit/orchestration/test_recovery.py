import pytest

from nexus.orchestration.recovery.checkpoint import Checkpoint
from nexus.orchestration.recovery.error_handler import ErrorHandler
from nexus.orchestration.recovery.fallback import Fallback
from nexus.orchestration.recovery.retry_logic import RetryExhausted, RetryLogic


@pytest.mark.asyncio
async def test_retry_logic_succeeds_after_transient_failures():
    calls = {"n": 0}

    async def _flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("simulated timeout")
        return "ok"

    retry = RetryLogic(max_attempts=5, base_delay=0.01, max_delay=0.02)
    result = await retry.run(_flaky)

    assert result == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_retry_logic_gives_up_after_max_attempts():
    async def _always_fails():
        raise TimeoutError("nope")

    retry = RetryLogic(max_attempts=2, base_delay=0.01, max_delay=0.02)
    with pytest.raises(RetryExhausted):
        await retry.run(_always_fails)


def test_error_handler_classifies_guardrail_vs_transient_vs_permanent():
    assert ErrorHandler.classify("Guardrail blocked: out of scope") == "guardrail"
    assert ErrorHandler.classify("Tool exceeded timeout of 30s") == "transient"
    assert ErrorHandler.classify("connection reset by peer") == "transient"
    assert ErrorHandler.classify("KeyError: no such thing") == "permanent"


def test_error_handler_should_retry_only_transient():
    assert ErrorHandler.should_retry("rate limit exceeded (429)") is True
    assert ErrorHandler.should_retry("Guardrail blocked: scope") is False
    assert ErrorHandler.should_retry("ValueError: bad input") is False


def test_fallback_agent_for_known_and_unknown():
    assert Fallback.agent_for("webapp_agent") == "recon_agent"
    assert Fallback.agent_for("recon_agent") is None


def test_fallback_degraded_result_is_truthfully_failed():
    result = Fallback.degraded_result("exploit_agent", "10.0.0.1", "pwn it", "no fallback available")
    assert result["status"] == "failed"
    assert result["metadata"]["degraded"] is True


def test_checkpoint_save_load_and_clear_round_trip(tmp_path):
    cp = Checkpoint(checkpoint_dir=tmp_path)
    assert cp.load("mission-x") is None
    assert cp.exists("mission-x") is False

    cp.save("mission-x", {"batch": 1, "completed": ["A"]})
    assert cp.exists("mission-x") is True
    assert cp.load("mission-x") == {"batch": 1, "completed": ["A"]}

    cp.clear("mission-x")
    assert cp.exists("mission-x") is False


def test_checkpoint_slugs_unsafe_mission_ids(tmp_path):
    cp = Checkpoint(checkpoint_dir=tmp_path)
    cp.save("../../etc/passwd", {"batch": 1})
    # Must have written *inside* tmp_path, not escaped it.
    written = list(tmp_path.iterdir())
    assert len(written) == 1
    assert written[0].parent == tmp_path
