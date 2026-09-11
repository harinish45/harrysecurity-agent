import concurrent.futures
import time
from collections import OrderedDict

import pytest

from nexus.foundation.guardrails.rate_guard import RateGuard, RateGuardError


@pytest.fixture(autouse=True)
def _isolate_rate_guard(monkeypatch):
    """Give every test a clean, isolated RateGuard state."""
    monkeypatch.setattr(RateGuard, "_windows", OrderedDict())
    monkeypatch.setattr(RateGuard, "_call_count", 0)
    yield
    monkeypatch.setattr(RateGuard, "_windows", OrderedDict())
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


def test_distinct_key_flood_cannot_grow_windows_unbounded(monkeypatch):
    """Regression for the unbounded-`_windows`-growth DoS.

    A caller that sends a fresh, textually-unique target on every call (e.g.
    randomised subdomains under a wildcard scope entry) used to be able to
    grow `_windows` without any bound -- only the time-based PRUNE_EVERY
    sweep could ever shrink it, and only once a key's own timestamps had
    fully expired, long after memory was already exhausted. MAX_KEYS must
    cap the dict size on every single call, well before any prune sweep.
    """
    monkeypatch.setenv("NEXUS_RATE_LIMIT", "1000000")
    monkeypatch.setenv("NEXUS_RATE_WINDOW", "60")
    monkeypatch.setattr(RateGuard, "MAX_KEYS", 50)

    # Far more distinct keys than MAX_KEYS, all within a single prune period
    # (well under PRUNE_EVERY calls), none of which should ever expire.
    for i in range(500):
        assert RateGuard.validate(target=f"flood-{i}.example.com")
        # The cap is enforced immediately on every call, not just every
        # PRUNE_EVERY-th one -- so it must never be exceeded, at any point.
        assert len(RateGuard._windows) <= 50

    assert len(RateGuard._windows) == 50
    # The most recently seen keys must survive eviction; the earliest ones,
    # having gone longest without being touched, must be the ones dropped.
    assert "flood-499.example.com" in RateGuard._windows
    assert "flood-0.example.com" not in RateGuard._windows


def test_key_cap_evicts_least_recently_touched_not_active_key(monkeypatch):
    """A key that keeps getting real traffic must survive eviction.

    Eviction must pick the least-recently-touched key, so a genuinely
    active target's rate-limit history is never the one silently reset by
    unrelated flood traffic filling up the cap.
    """
    monkeypatch.setenv("NEXUS_RATE_LIMIT", "1000000")
    monkeypatch.setenv("NEXUS_RATE_WINDOW", "60")
    monkeypatch.setattr(RateGuard, "MAX_KEYS", 10)

    active_target = "steady-active-target"
    RateGuard.validate(target=active_target)

    for i in range(100):
        RateGuard.validate(target=f"other-{i}")
        # Re-touch the active target every few calls so it stays "recent".
        if i % 3 == 0:
            RateGuard.validate(target=active_target)

    assert len(RateGuard._windows) <= 10
    assert active_target in RateGuard._windows


def test_max_keys_misconfigured_to_zero_or_negative_is_clamped(monkeypatch):
    """NEXUS_RATE_MAX_KEYS=0 (or negative) used to defeat the cap silently:
    the current call's own key is always present and is never evicted (see
    keep_key in _evict_oldest_locked), so eviction would stop at exactly 1
    entry no matter how low the configured cap was set -- contradicting the
    "never exceeds MAX_KEYS" guarantee for that misconfiguration. validate()
    now clamps max_keys to >=1 before using it, so the guarantee holds even
    for a nonsensical operator-supplied value.
    """
    monkeypatch.setenv("NEXUS_RATE_LIMIT", "1000000")
    monkeypatch.setenv("NEXUS_RATE_WINDOW", "60")
    monkeypatch.setenv("NEXUS_RATE_MAX_KEYS", "0")

    for i in range(20):
        assert RateGuard.validate(target=f"zero-cap-{i}.example.com")

    assert len(RateGuard._windows) == 1
