from __future__ import annotations

import time

import pytest

from nexus.platform import ExecutionCache, SandboxPolicy


def test_execution_cache_round_trip_and_dedup(tmp_path):
    cache = ExecutionCache(tmp_path / "cache.sqlite3", ttl_seconds=60)
    key = "abc123"
    cache.put(key, {"finding": "x", "score": 9.1})
    assert cache.get(key) == {"finding": "x", "score": 9.1}
    cache.put(key, {"finding": "updated"})
    assert cache.get(key) == {"finding": "updated"}


def test_execution_cache_expires(tmp_path):
    cache = ExecutionCache(tmp_path / "cache.sqlite3", ttl_seconds=1)
    cache.put("expired", {"ok": True})
    time.sleep(1.05)
    assert cache.get("expired") is None


def test_sandbox_policy_is_conservative():
    policy = SandboxPolicy()
    policy.validate()
    args = policy.docker_args()
    assert "--network" in args
    assert "none" in args
    assert "--read-only" in args
    assert "--cap-drop" in args
    assert "ALL" in args


def test_sandbox_rejects_networked_runtime():
    policy = SandboxPolicy(network="bridge")
    with pytest.raises(ValueError, match="network=none"):
        policy.validate()


def test_sandbox_rejects_privilege_relaxation():
    with pytest.raises(ValueError, match="no-new-privileges"):
        SandboxPolicy(no_new_privileges=False).validate()
    with pytest.raises(ValueError, match="capabilities"):
        SandboxPolicy(drop_all_capabilities=False).validate()
