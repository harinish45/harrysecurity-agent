"""Append-only, secret-safe audit events for tool execution."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any


class AuditGuardError(Exception):
    pass


class AuditGuard:
    _log_file = os.environ.get("NEXUS_AUDIT_LOG", os.path.join(os.getcwd(), "nexus_audit.log"))
    _sensitive_terms = ("password", "passwd", "secret", "token", "api_key", "apikey", "credential", "private_key")

    GENESIS_HASH = "0" * 64

    _last_hash: str | None = None

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
    def validate(cls, action: str, target: str | None = None, **kwargs: Any) -> bool:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": str(action),
            "target": target,
            "kwargs": {key: cls._safe_value(key, value) for key, value in kwargs.items()},
        }
        prev_hash = cls._get_last_hash()
        entry["prev_hash"] = prev_hash
        entry["hash"] = cls._compute_hash(prev_hash, entry)
        try:
            with open(cls._log_file, "a", encoding="utf-8") as file:
                file.write(json.dumps(entry, sort_keys=True) + "\n")
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
