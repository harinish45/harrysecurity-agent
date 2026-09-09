"""Append-only, secret-safe audit events for tool execution."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from datetime import datetime, timezone
from typing import Any


class AuditGuardError(Exception):
    pass


def _restrict(path: str) -> None:
    """Best-effort 0600 permissions, matching nexus/foundation/secrets.py's
    vault-file treatment. An audit log that's world-readable/writable
    undermines the point of a tamper-evident chain regardless of the hash
    chain itself: anyone on the host could read sensitive audit data, or
    (though the chain would then fail verification) overwrite entries.
    Silently ignored on filesystems that don't support POSIX mode bits."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


class AuditGuard:
    _log_file = os.environ.get("NEXUS_AUDIT_LOG", os.path.join(os.getcwd(), "nexus_audit.log"))
    _sensitive_terms = ("password", "passwd", "secret", "token", "api_key", "apikey", "credential", "private_key")
    _max_bytes_env = "NEXUS_AUDIT_LOG_MAX_MB"
    _default_max_mb = 100

    GENESIS_HASH = "0" * 64

    _last_hash: str | None = None
    # `ToolExecutor` calls `validate()` synchronously before every tool call,
    # and tool calls genuinely run concurrently (FlowController batches
    # agents across a thread pool). Without a lock, two threads can read the
    # same prev_hash, both append an entry claiming it, and corrupt the
    # chain — `verify_chain()` would then report a legitimate concurrent
    # audit log as tampered. This lock makes read-prev-hash -> compute ->
    # write -> update-last-hash one atomic critical section, same pattern as
    # RateGuard's `_lock` elsewhere in this package.
    _lock = threading.Lock()

    @classmethod
    def _safe_value(cls, key: str, value: Any) -> Any:
        if any(term in key.lower() for term in cls._sensitive_terms):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {str(child_key): cls._safe_value(str(child_key), child_value) for child_key, child_value in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._safe_value(key, item) for item in value]
        return str(value)

    @classmethod
    def _compute_hash(cls, prev_hash: str, entry_without_hash: dict) -> str:
        """Recompute the chain hash for an entry given its prev_hash.

        ``entry_without_hash`` must NOT contain the "hash" key (it may contain
        "prev_hash"; that field is included via the serialized JSON, and is
        also passed explicitly as ``prev_hash`` for clarity/consistency).
        """
        serialized = json.dumps(entry_without_hash, sort_keys=True)
        return hashlib.sha256((prev_hash + serialized).encode("utf-8")).hexdigest()

    @classmethod
    def _get_last_hash(cls) -> str:
        """Lazily initialize `_last_hash` by reading the tail of the log file."""
        if cls._last_hash is not None:
            return cls._last_hash
        last_hash = cls.GENESIS_HASH
        try:
            if os.path.exists(cls._log_file):
                with open(cls._log_file, "r", encoding="utf-8") as file:
                    last_line = None
                    for line in file:
                        line = line.strip()
                        if line:
                            last_line = line
                    if last_line is not None:
                        record = json.loads(last_line)
                        last_hash = record.get("hash", cls.GENESIS_HASH)
        except (OSError, json.JSONDecodeError):
            last_hash = cls.GENESIS_HASH
        cls._last_hash = last_hash
        return last_hash

    @classmethod
    def _max_bytes(cls) -> int:
        try:
            max_mb = float(os.environ.get(cls._max_bytes_env, cls._default_max_mb))
        except ValueError:
            max_mb = cls._default_max_mb
        return int(max_mb * 1024 * 1024)

    @classmethod
    def _rotate_if_needed_locked(cls) -> None:
        """Called with cls._lock already held. Archives the live log file
        once it crosses the size threshold and starts a fresh chain.

        Each archived segment remains independently verifiable from
        GENESIS_HASH (verify_chain() needs no cross-file awareness to check
        any one segment) — rotation does NOT continue the same hash chain
        across the file boundary, because splicing a chain across a rename
        the way this method does it can't be made atomic with the OLD
        file's last real write under this same lock without re-opening and
        re-hashing it, and a chain that silently spans files is also a
        chain `verify_chain()` can't check without being told to look
        elsewhere. Instead, continuity is recorded explicitly: the new
        segment's very first entry is a real audit event (not a synthetic
        placeholder) carrying the archived file's name and its real final
        hash in `kwargs`, so a reader can walk backwards through the
        archive sequence and confirm segment N+1 correctly cites segment
        N's true last hash — tamper-evidence across the rotation boundary,
        without a cross-file chain.
        """
        path = cls._log_file
        try:
            if not os.path.exists(path) or os.path.getsize(path) < cls._max_bytes():
                return
        except OSError:
            return

        last_hash_of_segment = cls._get_last_hash()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        archive_path = f"{path}.{timestamp}.archive"
        try:
            os.replace(path, archive_path)
        except OSError as exc:
            raise AuditGuardError(f"Audit log rotation failed: {exc}") from exc
        _restrict(archive_path)
        cls._last_hash = None  # force _get_last_hash() to see the (now-missing) fresh file -> GENESIS_HASH
        cls._pending_rotation_note = {
            "rotated_from": os.path.basename(archive_path),
            "rotated_from_final_hash": last_hash_of_segment,
        }

    _pending_rotation_note: dict[str, str] | None = None

    @classmethod
    def validate(cls, action: str, target: str | None = None, **kwargs: Any) -> bool:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": str(action),
            "target": target,
            "kwargs": {key: cls._safe_value(key, value) for key, value in kwargs.items()},
        }
        # Read-prev-hash -> compute -> write -> update-last-hash must be one
        # atomic step: this runs from ToolExecutor on every real tool call,
        # and tool calls genuinely execute concurrently across FlowController's
        # thread pool.
        with cls._lock:
            cls._rotate_if_needed_locked()
            if cls._pending_rotation_note is not None:
                entry["kwargs"] = {**entry["kwargs"], **cls._pending_rotation_note}
                cls._pending_rotation_note = None
            prev_hash = cls._get_last_hash()
            entry["prev_hash"] = prev_hash
            entry["hash"] = cls._compute_hash(prev_hash, entry)
            try:
                with open(cls._log_file, "a", encoding="utf-8") as file:
                    file.write(json.dumps(entry, sort_keys=True) + "\n")
                _restrict(cls._log_file)
            except OSError as exc:
                raise AuditGuardError(f"Audit log write failed: {exc}") from exc
            cls._last_hash = entry["hash"]
        return True

    @classmethod
    def verify_chain(cls, log_file: str | None = None) -> tuple[bool, int | None]:
        """Verify the hash chain of the audit log.

        Returns (True, None) if every entry's hash and prev_hash link is
        intact, or (False, line_number) for the first (1-indexed) line that
        fails verification.
        """
        path = log_file if log_file is not None else cls._log_file
        expected_prev = cls.GENESIS_HASH
        try:
            with open(path, "r", encoding="utf-8") as file:
                lines = file.readlines()
        except OSError:
            return True, None

        line_number = 0
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            line_number += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, line_number

            stored_hash = record.get("hash")
            stored_prev_hash = record.get("prev_hash")
            if stored_hash is None or stored_prev_hash is None:
                return False, line_number

            if stored_prev_hash != expected_prev:
                return False, line_number

            entry_without_hash = {key: value for key, value in record.items() if key != "hash"}
            recomputed_hash = cls._compute_hash(stored_prev_hash, entry_without_hash)
            if recomputed_hash != stored_hash:
                return False, line_number

            expected_prev = stored_hash

        return True, None

    @classmethod
    def log(cls, message: str, level: str = "info") -> None:
        return None
