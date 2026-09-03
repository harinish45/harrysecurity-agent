import concurrent.futures
import time

import pytest

from nexus.foundation.guardrails.rate_guard import RateGuard, RateGuardError


@pytest.fixture(autouse=True)
def _isolate_rate_guard(monkeypatch):
    """Give every test a clean, isolated RateGuard state."""
    monkeypatch.setattr(RateGuard, "_windows", {})
    monkeypatch.setattr(RateGuard, "_call_count", 0)
    yield
    monkeypatch.setattr(RateGuard, "_windows", {})
    monkeypatch.setattr(RateGuard, "_call_count", 0)


def test_concurrent_requests_never_exceed_limit(monkeypatch):
    monkeypatch.setenv("NEXUS_RATE_LIMIT", "50")
    monkeypatch.setenv("NEXUS_RATE_WINDOW", "60")

    target = "concurrent-target"
    thread_count = 200
    successes = 0
    failures = 0

    def hit():
        try:
            RateGuard.validate(target=target)
            return True
        except RateGuardError:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: hit(), range(thread_count)))

    successes = sum(1 for r in results if r)
    failures = sum(1 for r in results if not r)

    # Atomicity: exactly `limit` requests should succeed, no more (the lock
    # covers check+append together so the count can never overshoot).
    assert successes == 50
    assert failures == thread_count - 50
    # Every call (success or failure) records a timestamp, so the window
    # ends up with one entry per call -- what matters for atomicity is that
    # successes never exceeded the limit above.
    assert len(RateGuard._windows[target]) == thread_count


def test_prune_does_not_break_active_key(monkeypatch):
    monkeypatch.setenv("NEXUS_RATE_LIMIT", "1000000")
    monkeypatch.setenv("NEXUS_RATE_WINDOW", "60")

    active_target = "active-target"

    # Seed a handful of stale keys with already-expired timestamps so a
    # prune sweep should drop them.
    stale_time = time.time() - 3600
    for i in range(5):
        RateGuard._windows[f"stale-{i}"] = [stale_time]

    # Drive enough calls on the active key to trigger at least one prune
    # sweep (PRUNE_EVERY calls) while confirming the active key keeps
    # working correctly throughout.
    calls = RateGuard.PRUNE_EVERY + 10
    for i in range(calls):
        assert RateGuard.validate(target=active_target)

    assert len(RateGuard._windows[active_target]) == calls
    # Stale keys should have been pruned away.
    for i in range(5):
        assert f"stale-{i}" not in RateGuard._windows


def test_reset_clears_target():
    RateGuard.validate(target="to-reset")
    assert "to-reset" in RateGuard._windows
    RateGuard.reset(target="to-reset")
    assert "to-reset" not in RateGuard._windows
