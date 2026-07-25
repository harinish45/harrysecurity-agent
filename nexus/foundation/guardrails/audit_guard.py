"""Append-only, secret-safe audit events for tool execution."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any


class AuditGuardError(Exception):
    pass


class AuditGuard:
    _log_file = os.environ.get("NEXUS_AUDIT_LOG", os.path.join(os.getcwd(), "nexus_audit.log"))
    _sensitive_terms = ("password", "passwd", "secret", "token", "api_key", "apikey", "credential", "private_key")

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
    def validate(cls, action: str, target: str | None = None, **kwargs: Any) -> bool:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": str(action),
            "target": target,
            "kwargs": {key: cls._safe_value(key, value) for key, value in kwargs.items()},
        }
        try:
            with open(cls._log_file, "a", encoding="utf-8") as file:
                file.write(json.dumps(entry, sort_keys=True) + "\n")
        except OSError as exc:
            raise AuditGuardError(f"Audit log write failed: {exc}") from exc
        return True

    @classmethod
    def log(cls, message: str, level: str = "info") -> None:
        return None
