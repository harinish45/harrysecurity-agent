"""Tests for nexus.advanced.honeypot.

Real functional test: start a CanaryListener on an OS-assigned free port,
connect to it with a plain socket, assert an AuditGuard audit-log entry
appeared for the connection, stop the listener, and assert the port no
longer accepts connections.
"""
import json
import socket
import time

import pytest

from nexus.advanced.honeypot import CanaryListener
from nexus.foundation.guardrails.audit_guard import AuditGuard


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    log_file = tmp_path / "audit.log"
    monkeypatch.setattr(AuditGuard, "_log_file", str(log_file))
    monkeypatch.setattr(AuditGuard, "_last_hash", None)
    return log_file


def _read_entries(log_file):
    if not log_file.exists():
        return []
    with open(log_file, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_start_returns_bound_port_and_is_running():
    canary = CanaryListener(host="127.0.0.1", port=0)
    try:
        port = canary.start()
        assert isinstance(port, int) and port > 0
        assert canary.is_running is True
        assert canary.bound_port == port
    finally:
        canary.stop()


def test_connection_is_logged_via_audit_guard(audit_log):
    canary = CanaryListener(host="127.0.0.1", port=0)
    port = canary.start()
    try:
        peer_port = None
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            peer_port = s.getsockname()[1]
        # Give the background handler thread a moment to write the audit entry.
        deadline = time.time() + 5
        entries = []
        while time.time() < deadline:
            entries = [e for e in _read_entries(audit_log) if e["action"] == "honeypot.connection"]
            if entries:
                break
            time.sleep(0.05)

        assert entries, "expected at least one honeypot.connection audit entry"
        entry = entries[-1]
        assert entry["target"] == f"127.0.0.1:{peer_port}"
        assert entry["kwargs"]["local_port"] == str(port)
    finally:
        canary.stop()


def test_stop_closes_the_port():
    canary = CanaryListener(host="127.0.0.1", port=0)
    port = canary.start()
    canary.stop()

    assert canary.is_running is False
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2)


def test_start_twice_without_stop_raises():
    canary = CanaryListener(host="127.0.0.1", port=0)
    canary.start()
    try:
        with pytest.raises(RuntimeError):
            canary.start()
    finally:
        canary.stop()
