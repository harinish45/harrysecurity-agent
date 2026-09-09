"""Local resource and concurrency controls for tool scheduling."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from time import monotonic

from nexus.tools.profile import ToolProfile


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    reason: str = ""
    retry_after_seconds: float = 0.0


class ToolLimiter:
    """In-process concurrency/rate limiter keyed by tool identity."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._active: defaultdict[str, int] = defaultdict(int)
        self._starts: defaultdict[str, deque[float]] = defaultdict(deque)

    def acquire(self, profile: ToolProfile) -> LimitDecision:
        now = monotonic()
        with self._lock:
            active = self._active[profile.name]
            if active >= profile.max_concurrency:
                return LimitDecision(False, "tool concurrency limit reached")

            starts = self._starts[profile.name]
            if profile.rate_limit_per_minute is not None:
                cutoff = now - 60.0
                while starts and starts[0] <= cutoff:
                    starts.popleft()
                if len(starts) >= profile.rate_limit_per_minute:
                    retry_after = max(0.0, 60.0 - (now - starts[0]))
                    return LimitDecision(False, "tool rate limit reached", retry_after)

            self._active[profile.name] = active + 1
            starts.append(now)
            return LimitDecision(True)

    def release(self, profile: ToolProfile) -> None:
        with self._lock:
            if self._active[profile.name] > 0:
                self._active[profile.name] -= 1

    def active_count(self, tool_name: str) -> int:
        with self._lock:
            return self._active[tool_name]
