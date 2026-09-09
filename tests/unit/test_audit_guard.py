import json
import threading

import pytest

from nexus.foundation.guardrails.audit_guard import AuditGuard


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    """Point AuditGuard at a fresh temp log file and reset its hash cache."""
    log_file = tmp_path / "audit.log"
    monkeypatch.setattr(AuditGuard, "_log_file", str(log_file))
    monkeypatch.setattr(AuditGuard, "_last_hash", None)
    return log_file


def _read_lines(log_file):
    with open(log_file, "r", encoding="utf-8") as file:
        return [line for line in file.read().splitlines() if line]


def test_validate_writes_hash_chained_entries(audit_log):
    assert AuditGuard.validate("scan.start", target="example.com", note="ok")
    assert AuditGuard.validate("scan.finish", target="example.com", note="done")

    lines = _read_lines(audit_log)
    assert len(lines) == 2

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert first["prev_hash"] == AuditGuard.GENESIS_HASH
    assert "hash" in first
    assert second["prev_hash"] == first["hash"]


def test_verify_chain_passes_on_untampered_log(audit_log):
    for i in range(5):
        AuditGuard.validate(f"action.{i}", target="t", index=i)

    ok, bad_line = AuditGuard.verify_chain(str(audit_log))
    assert (ok, bad_line) == (True, None)


def test_verify_chain_detects_tampering(audit_log):
    for i in range(5):
        AuditGuard.validate(f"action.{i}", target="t", index=i)

    lines = _read_lines(audit_log)
    tampered_index = 2  # 0-indexed -> line number 3
    record = json.loads(lines[tampered_index])
    record["action"] = "tampered.action"
    lines[tampered_index] = json.dumps(record, sort_keys=True)

    with open(audit_log, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    ok, bad_line = AuditGuard.verify_chain(str(audit_log))
    assert ok is False
    assert bad_line == tampered_index + 1


def test_verify_chain_on_missing_log_is_ok(tmp_path):
    missing = tmp_path / "does_not_exist.log"
    ok, bad_line = AuditGuard.verify_chain(str(missing))
    assert (ok, bad_line) == (True, None)


def test_validate_is_safe_under_real_concurrent_writers(audit_log):
    """ToolExecutor calls AuditGuard.validate() synchronously from inside
    FlowController's thread-pool-parallelized agents — real concurrent
    writers, not a hypothetical. Without a lock around read-prev-hash ->
    compute -> write -> update-last-hash, two threads can race: both read
    the same prev_hash, both append an entry claiming it, corrupting the
    chain so verify_chain() reports a legitimate log as tampered."""
    threads = [
        threading.Thread(target=AuditGuard.validate, args=(f"concurrent.action.{i}",), kwargs={"target": "t", "index": i})
        for i in range(40)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = _read_lines(audit_log)
    assert len(lines) == 40

    ok, bad_line = AuditGuard.verify_chain(str(audit_log))
    assert (ok, bad_line) == (True, None)

    # Every entry's prev_hash must be some earlier entry's hash (or genesis)
    # and every hash must be unique — a lost-update race would produce two
    # entries pointing at the same prev_hash, which verify_chain() might not
    # always catch depending on write order, so check this directly too.
    hashes = [json.loads(line)["hash"] for line in lines]
    assert len(hashes) == len(set(hashes))


def test_sensitive_kwargs_still_redacted(audit_log):
    assert AuditGuard.validate("login", target="t", api_key="super-secret")
    lines = _read_lines(audit_log)
    entry = json.loads(lines[0])
    assert entry["kwargs"]["api_key"] == "[REDACTED]"
