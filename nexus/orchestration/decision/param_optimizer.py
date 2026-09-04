"""Adjusts per-call tool parameters by target scope. Currently just timeout
(the one parameter the executor actually honours an override for — see
ToolExecutor.run's `timeout` kwarg) — private/loopback targets resolve fast,
so there's no reason to hold a concurrency slot for the full
public-internet timeout budget."""
from __future__ import annotations

from nexus.foundation.config import config
from nexus.foundation.ssl_config import _is_private_scope


class ParamOptimizer:
    @staticmethod
    def timeout_for(target: str, base_timeout: float | None = None) -> float:
        base = base_timeout if base_timeout is not None else float(getattr(config, "nexus_tool_timeout", 300))
        try:
            private = _is_private_scope(target)
        except Exception:
            private = False
        return max(15.0, base / 3) if private else base
