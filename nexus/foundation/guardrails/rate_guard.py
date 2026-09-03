import time, json, os, threading
from rich.console import Console

console = Console()

class RateGuardError(Exception):
    pass

class RateGuard:
    _windows = {}
    _lock = threading.Lock()
    DEFAULT_LIMIT = 100
    DEFAULT_WINDOW = 60.0
    PRUNE_EVERY = 200  # sweep stale keys roughly every Nth call, not every call

    _call_count = 0

    @classmethod
    def validate(cls, target=None, requests=1, **kwargs):
        key = target or "global"
        now = time.time()
        limit = int(os.environ.get("NEXUS_RATE_LIMIT", cls.DEFAULT_LIMIT))
        window = float(os.environ.get("NEXUS_RATE_WINDOW", cls.DEFAULT_WINDOW))
        with cls._lock:
            ts_list = cls._windows.setdefault(key, [])
            ts_list[:] = [t for t in ts_list if now - t < window]
            ts_list.append(now)
            if len(ts_list) > limit:
                console.print(f"[red][RATE GUARD] Too many requests to {key}: {len(ts_list)} > {limit}/{window}s[/red]")
                raise RateGuardError(f"Rate limit exceeded for {key}")

            cls._call_count += 1
            if cls._call_count % cls.PRUNE_EVERY == 0:
                cls._prune_locked(now, window, keep_key=key)
        console.print(f"[green][RATE GUARD] Request allowed: {key} ({len(ts_list)}/{limit})[/green]")
        return True

    @classmethod
    def _prune_locked(cls, now, window, keep_key=None):
        """Drop keys whose timestamp lists are empty after expiry filtering.

        Must be called while holding cls._lock.
        """
        stale_keys = []
        for existing_key, existing_ts in cls._windows.items():
            if existing_key == keep_key:
                continue
            existing_ts[:] = [t for t in existing_ts if now - t < window]
            if not existing_ts:
                stale_keys.append(existing_key)
        for stale_key in stale_keys:
            cls._windows.pop(stale_key, None)

    @classmethod
    def reset(cls, target=None):
        key = target or "global"
        with cls._lock:
            cls._windows.pop(key, None)

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][RateGuard] {message}[/dim]")
