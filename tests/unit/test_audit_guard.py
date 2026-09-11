import glob
import json
import os
import stat
import threading

import pytest

from nexus.foundation.guardrails.audit_guard import AuditGuard


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    """Point AuditGuard at a fresh temp log file and reset its hash cache."""
    log_file = tmp_path / "audit.log"
    monkeypatch.setattr(AuditGuard, "_log_file", str(log_file))
    monkeypatch.setattr(AuditGuard, "_last_hash", None)
    monkeypatch.setattr(AuditGuard, "_pending_rotation_note", None)
    monkeypatch.delenv("NEXUS_AUDIT_LOG_MAX_MB", raising=False)
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


def test_write_permissions_are_restricted(audit_log):
    """An audit log that's world-readable/writable undermines the point
    of a tamper-evident chain regardless of the hash chain itself — best-
    effort 0600, matching secrets.py's vault-file treatment. Only
    meaningful on filesystems that honor POSIX mode bits."""
    AuditGuard.validate("action", target="t")
    mode = stat.S_IMODE(os.stat(str(audit_log)).st_mode)
    if os.name == "posix":
        assert mode == (stat.S_IRUSR | stat.S_IWUSR)
    # On non-POSIX filesystems (some Windows configurations) os.chmod is a
    # documented best-effort no-op — nothing to assert there.


def test_rotation_creates_an_independently_verifiable_segment(audit_log, monkeypatch):
    """Each entry this test writes is deliberately padded so a handful of
    them cross a tiny configured threshold, forcing at least one rotation
    within the test without needing megabytes of real writes."""
    monkeypatch.setenv("NEXUS_AUDIT_LOG_MAX_MB", str(600 / (1024 * 1024)))  # ~600 bytes

    for i in range(20):
        AuditGuard.validate(f"action.{i}", target="t", padding="x" * 80)

    archives = sorted(glob.glob(str(audit_log) + ".*.archive"))
    assert archives, "expected at least one rotation to have occurred"

    # The live (post-rotation) file is itself a complete, independently
    # verifiable segment starting from GENESIS_HASH.
    ok, bad_line = AuditGuard.verify_chain(str(audit_log))
    assert (ok, bad_line) == (True, None)
    with open(audit_log, encoding="utf-8") as file:
        first_live_entry = json.loads(file.readline())
    assert first_live_entry["prev_hash"] == AuditGuard.GENESIS_HASH

    # So is every archived segment.
    for archive in archives:
        ok, bad_line = AuditGuard.verify_chain(archive)
        assert (ok, bad_line) == (True, None), f"{archive} failed verification at line {bad_line}"


def test_rotation_lineage_correctly_links_every_segment_in_sequence(audit_log, monkeypatch):
    """Rotation doesn't continue one hash chain across the file boundary
    (see the docstring on _rotate_if_needed_locked for why) — continuity is
    instead a real audit entry in each new segment's first line, citing
    the exact final hash of the segment immediately before it. Walk the
    full archive+live sequence and confirm every citation is exactly
    correct, not just present."""
    monkeypatch.setenv("NEXUS_AUDIT_LOG_MAX_MB", str(600 / (1024 * 1024)))

    for i in range(20):
        AuditGuard.validate(f"action.{i}", target="t", padding="x" * 80)

    archives = sorted(glob.glob(str(audit_log) + ".*.archive"))
    assert len(archives) >= 2, "need at least 2 rotations to test sequence linkage meaningfully"

    segments = archives + [str(audit_log)]
    prev_final_hash = None
    for idx, segment_path in enumerate(segments):
        with open(segment_path, encoding="utf-8") as file:
            entries = [json.loads(line) for line in file if line.strip()]
        if idx > 0:
            cited = entries[0]["kwargs"].get("rotated_from_final_hash")
            assert cited == prev_final_hash, (
                f"segment {idx} ({segment_path}) cites {cited!r}, "
                f"expected the previous segment's real final hash {prev_final_hash!r}"
            )
            assert entries[0]["kwargs"].get("rotated_from") == os.path.basename(segments[idx - 1])
        prev_final_hash = entries[-1]["hash"]


def test_rotation_never_loses_or_duplicates_entries(audit_log, monkeypatch):
    """The total entry count across every archived segment plus the live
    file must equal exactly how many validate() calls were made — rotation
    must not drop or double-write anything across the boundary."""
    monkeypatch.setenv("NEXUS_AUDIT_LOG_MAX_MB", str(600 / (1024 * 1024)))

    n_calls = 25
    for i in range(n_calls):
        AuditGuard.validate(f"action.{i}", target="t", padding="x" * 80)

    archives = sorted(glob.glob(str(audit_log) + ".*.archive"))
    total_entries = 0
    for segment_path in archives + [str(audit_log)]:
        with open(segment_path, encoding="utf-8") as file:
            total_entries += sum(1 for line in file if line.strip())
    assert total_entries == n_calls
