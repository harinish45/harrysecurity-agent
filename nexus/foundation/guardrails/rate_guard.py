import time, json, os, threading
from collections import OrderedDict
from rich.console import Console

console = Console()

class RateGuardError(Exception):
    pass

class RateGuard:
    # OrderedDict (not plain dict) so we can maintain least-recently-touched
    # order: every validate() call moves its key to the end, so the front of
    # the dict is always the key that has gone longest without a request --
    # exactly what MAX_KEYS eviction below needs to pick a safe victim.
    _windows = OrderedDict()
    _lock = threading.Lock()
    DEFAULT_LIMIT = 100
    DEFAULT_WINDOW = 60.0
    PRUNE_EVERY = 200  # sweep stale keys roughly every Nth call, not every call
    # Hard ceiling on the number of distinct target keys tracked at once.
    # `_windows` used to be keyed by the raw, caller-supplied target string
    # with no cap on distinct keys -- only the time-based PRUNE_EVERY sweep,
    # which evicts a key only once ITS OWN timestamps have fully expired. A
    # caller who sends a fresh, textually-unique target on every call (e.g.
    # random subdomains under a wildcard scope entry, or trivial case/port/
    # scheme variations of one host) could grow `_windows` without bound
    # within a single window, before any of those short-lived entries were
    # eligible for pruning -- a memory-exhaustion DoS, and it simultaneously
    # let an attacker dodge the per-target limit entirely by rotating keys.
    # Enforcing MAX_KEYS on every call (not just every PRUNE_EVERY-th one)
    # evicts the least-recently-touched key immediately once the ceiling is
    # hit, so `_windows` can never exceed MAX_KEYS entries no matter how
    # many distinct keys a caller manufactures.
    MAX_KEYS = 5000

    _call_count = 0

    @classmethod
    def validate(cls, target=None, requests=1, **kwargs):
        key = target or "global"
        now = time.time()
        limit = int(os.environ.get("NEXUS_RATE_LIMIT", cls.DEFAULT_LIMIT))
        window = float(os.environ.get("NEXUS_RATE_WINDOW", cls.DEFAULT_WINDOW))
        # Clamp to >=1: the current call's own key is always present in
        # _windows and is never evicted (see keep_key in
        # _evict_oldest_locked), so a configured max_keys <= 0 could never
        # actually be reached -- eviction would stop at exactly 1 entry,
        # silently breaking the "never exceeds MAX_KEYS" guarantee below for
        # that misconfiguration.
        max_keys = max(1, int(os.environ.get("NEXUS_RATE_MAX_KEYS", cls.MAX_KEYS)))
        with cls._lock:
            is_new_key = key not in cls._windows
            ts_list = cls._windows.setdefault(key, [])
            cls._windows.move_to_end(key)
            ts_list[:] = [t for t in ts_list if now - t < window]
            ts_list.append(now)

            if is_new_key and len(cls._windows) > max_keys:
                cls._evict_oldest_locked(max_keys, keep_key=key)

            if len(ts_list) > limit:
                console.print(f"[red][RATE GUARD] Too many requests to {key}: {len(ts_list)} > {limit}/{window}s[/red]")
                raise RateGuardError(f"Rate limit exceeded for {key}")

            cls._call_count += 1
            if cls._call_count % cls.PRUNE_EVERY == 0:
                cls._prune_locked(now, window, keep_key=key)
        console.print(f"[green][RATE GUARD] Request allowed: {key} ({len(ts_list)}/{limit})[/green]")
        return True

    @classmethod
    def _evict_oldest_locked(cls, max_keys, keep_key=None):
        """Drop the least-recently-touched key(s) until back within max_keys.

        Must be called while holding cls._lock. `_windows` is kept in
        least-recently-touched order (every validate() call moves its key to
        the end), so popping from the front evicts whichever key has gone
        longest without a request -- the natural victim for a bounded cache,
        and never the key that triggered this eviction.
        """
        while len(cls._windows) > max_keys:
            oldest_key = next(iter(cls._windows))
            if oldest_key == keep_key:
                break
            cls._windows.pop(oldest_key, None)

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
