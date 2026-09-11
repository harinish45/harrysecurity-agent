"""Exponential-backoff retry for async work, used to ride out transient tool
failures (timeouts, connection resets, rate limits) instead of failing a
whole mission phase on the first hiccup."""
from __future__ import annotations

import asyncio
import random
from typing import Any, Awaitable, Callable


class RetryExhausted(Exception):
    pass


class RetryLogic:
    def __init__(self, max_attempts: int = 3, base_delay: float = 0.5, max_delay: float = 8.0) -> None:
        self.max_attempts = max(1, max_attempts)
        self.base_delay = base_delay
        self.max_delay = max_delay

    async def run(
        self,
        fn: Callable[[], Awaitable[Any]],
        *,
        retry_on: tuple[type[BaseException], ...] = (Exception,),
        on_retry: Callable[[int, BaseException, float], None] | None = None,
    ) -> Any:
        last_exc: BaseException | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                return await fn()
            except retry_on as exc:
                last_exc = exc
                if attempt == self.max_attempts:
                    break
                delay = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
                delay += random.uniform(0, delay * 0.25)
                if on_retry:
                    on_retry(attempt, exc, delay)
                await asyncio.sleep(delay)
        raise RetryExhausted(f"Failed after {self.max_attempts} attempt(s): {last_exc}") from last_exc
