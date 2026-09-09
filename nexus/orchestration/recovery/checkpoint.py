"""Mission-progress persistence, so a mission interrupted mid-run (crash,
restart) has a durable record of which batches completed and what context
had been handed forward — enough to inspect or resume from, rather than
losing all progress silently.

Checkpoints are signed (HMAC-SHA256) on write and verified on read. Without
this, anyone with filesystem write access to the checkpoint file (e.g.
`~/.nexus/checkpoints/<mission>.json`, or wherever `NEXUS_CHECKPOINT_DIR`
points) could hand-edit it — e.g. set `"batch"` equal to `"total_batches"` —
and have FlowController.run(resume=True) trust it verbatim, skipping every
real batch and returning fabricated `completed`/`context` as if it were
genuine mission output (see flow_controller.py's resume path). `load()` now
refuses (returns `None`, exactly as if no checkpoint existed) any file that
isn't signed with the key this process holds, so a tampered checkpoint makes
a resume fall back to running the mission fresh instead of replaying
attacker-supplied results."""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from nexus.foundation.logging import logger
from nexus.foundation.paths import safe_join, safe_slug

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


def _checkpoint_dir() -> Path:
    override = os.environ.get("NEXUS_CHECKPOINT_DIR")
    path = Path(override) if override else Path.home() / ".nexus" / "checkpoints"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _hmac_key_path() -> Path:
    # Deliberately NOT under the checkpoint directory (NEXUS_CHECKPOINT_DIR):
    # the signing key must not be reachable by an actor who only has write
    # access to the checkpoint files it's meant to protect.
    override = os.environ.get("NEXUS_VAULT_DIR")
    base = Path(override) if override else Path.home() / ".nexus"
    base.mkdir(parents=True, exist_ok=True)
    return base / "checkpoint_hmac.key"


def _restrict(path: Path) -> None:
    """Best-effort 0600 permissions. Silently ignored on filesystems that
    don't support POSIX mode bits (e.g. some Windows configurations)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _load_or_create_hmac_key() -> bytes:
    """The shared secret used to sign/verify checkpoint files: from
    `NEXUS_CHECKPOINT_KEY` if set, else a locally generated key persisted
    outside the checkpoint directory so the same key is used across the
    save() that wrote a checkpoint and every later load() that verifies it,
    including across process restarts."""
    env_material = os.environ.get("NEXUS_CHECKPOINT_KEY")
    if env_material:
        return env_material.encode("utf-8")

    key_path = _hmac_key_path()
    try:
        if key_path.exists():
            existing = key_path.read_bytes()
            if existing:
                return existing
    except OSError:
        pass

    key = os.urandom(32)
    try:
        key_path.write_bytes(key)
        _restrict(key_path)
    except OSError:
        logger.warning(
            "Could not persist checkpoint HMAC key at %s; using an ephemeral "
            "key for this process (checkpoints saved now won't verify after "
            "a restart).",
            key_path,
        )
    return key


def _sign(payload: str) -> str:
    return hmac.new(_load_or_create_hmac_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


# save() used to be a plain `path.write_text(...)`: no lock, no
# temp-file+rename, no compare-and-swap. Nothing dedupes concurrent runs by
# mission_id (nexus/mcp/server.py resolves a deterministic mission_id from
# `target` alone when the caller omits one), so two separate
# FlowController/Checkpoint instances for the SAME mission_id — two threads
# in one process, or two independently-launched processes pointed at the
# same NEXUS_CHECKPOINT_DIR — could race on the identical checkpoint file:
# two `write_text` calls landing near-simultaneously could interleave and
# produce invalid JSON (the next load() hits JSONDecodeError and silently
# returns None, losing all progress), or non-atomically overwrite each
# other with an unpredictable torn result.
#
# The two locks below don't (and can't, from inside this module) make
# concurrent saves for the same mission_id semantically safe — actually
# deduplicating concurrent runs by mission_id is the caller's job — but
# they guarantee every individual save() is atomic: a concurrent load()
# always observes either a complete prior write or a complete new one,
# never a torn/interleaved mix, and never spuriously invalid JSON.

# Per-process guard: serializes concurrent save() calls against the SAME
# checkpoint path across threads of this process, cheaply, before ever
# touching the filesystem.
_thread_locks_guard = threading.Lock()
_thread_locks: dict[Path, threading.Lock] = {}


def _thread_lock_for(path: Path) -> threading.Lock:
    with _thread_locks_guard:
        lock = _thread_locks.get(path)
        if lock is None:
            lock = threading.Lock()
            _thread_locks[path] = lock
        return lock


@contextlib.contextmanager
def _cross_process_lock(lock_path: Path):
    """Advisory OS-level lock on a `.lock` sidecar file, so two separate OS
    processes (two independently-launched CLI/MCP-server instances sharing
    a checkpoint directory) also serialize saves to the same checkpoint
    file, not just threads within one process."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+b")
    try:
        if sys.platform == "win32":
            # LK_LOCK retries internally for ~10s before raising; loop so a
            # longer-held lock doesn't spuriously fail a save.
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if sys.platform == "win32":
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def _replace_with_retry(src: str, dst: Path, *, attempts: int = 100, delay: float = 0.01) -> None:
    """os.replace() is atomic, but on Windows it can transiently raise
    PermissionError ("Access is denied") if another thread/process
    momentarily holds `dst` open — e.g. a concurrent load()'s
    `read_text()` — since Python's default open mode there doesn't set
    FILE_SHARE_DELETE. That handle is only ever held for the duration of a
    single read, so a short retry loop clears it reliably; it never
    weakens atomicity, since os.replace itself is never partial — it
    either fully lands or doesn't happen at all."""
    last_exc: OSError | None = None
    for _ in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:
            last_exc = exc
            time.sleep(delay)
    assert last_exc is not None
    raise last_exc


def _atomic_write(path: Path, payload: str) -> None:
    """Write `payload` to `path` without ever leaving a reader able to
    observe a partial/torn write: write to a temp file in the same
    directory, fsync it, then atomically replace `path` with it via
    os.replace — atomic on POSIX and on Windows alike (unlike os.rename,
    which raises on Windows if the destination already exists). A
    concurrent load() on another thread/process always sees either the
    fully-old or the fully-new file, never a mix of the two."""
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        _replace_with_retry(tmp_name, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


class Checkpoint:
    def __init__(self, checkpoint_dir: Path | None = None) -> None:
        self._dir = checkpoint_dir or _checkpoint_dir()

    def _path(self, mission_id: str) -> Path:
        return safe_join(self._dir, f"{safe_slug(mission_id)}.json")

    def save(self, mission_id: str, state: dict[str, Any]) -> Path:
        path = self._path(mission_id)
        payload = json.dumps(state, default=str, indent=2)
        envelope = json.dumps({"payload": payload, "hmac": _sign(payload)}, indent=2)
        lock_path = Path(f"{path}.lock")
        with _thread_lock_for(path), _cross_process_lock(lock_path):
            _atomic_write(path, envelope)
        return path

    def load(self, mission_id: str) -> dict[str, Any] | None:
        path = self._path(mission_id)
        if not path.exists():
            return None
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        if not isinstance(envelope, dict):
            logger.warning("Checkpoint %s is not a signed envelope; refusing to trust it.", mission_id)
            return None
        payload = envelope.get("payload")
        provided_hmac = envelope.get("hmac")
        if not isinstance(payload, str) or not isinstance(provided_hmac, str):
            logger.warning("Checkpoint %s is missing its signature; refusing to trust it.", mission_id)
            return None
        if not hmac.compare_digest(_sign(payload), provided_hmac):
            logger.warning(
                "Checkpoint %s failed integrity verification (HMAC mismatch) "
                "— the file was modified outside of Checkpoint.save() or "
                "signed with a different key. Refusing to resume from it.",
                mission_id,
            )
            return None

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None
        if not self._is_well_formed(data):
            return None
        return data

    @staticmethod
    def _is_well_formed(data: Any) -> bool:
        """A checkpoint file can be syntactically valid JSON while still
        having the wrong shape — hand-edited, truncated by a concurrent
        write, or written by an incompatible version — e.g. `"batch": "5"`
        (a string) instead of an int, or a `"tasks"` entry missing/with a
        non-hashable `"id"`. Every consumer of `load()`'s return value
        (FlowController._run's `batch_num <= already_done_through_batch`,
        its `{t["id"]: t for t in batch}`, OrchestrationEngine.run_mission)
        assumes the exact shape `save()` writes and has no defense of its
        own, so reject anything else here and let callers treat it the same
        as a missing/corrupt file (their existing degrade-safe contract)
        rather than let a malformed-but-parseable checkpoint reach them."""
        if not isinstance(data, dict):
            return False

        def _is_int(value: Any) -> bool:
            return isinstance(value, int) and not isinstance(value, bool)

        if "batch" in data and not _is_int(data["batch"]):
            return False
        if "total_batches" in data and not _is_int(data["total_batches"]):
            return False
        if "completed" in data and not isinstance(data["completed"], list):
            return False
        if "context" in data and not isinstance(data["context"], dict):
            return False

        tasks = data.get("tasks")
        if tasks is not None:
            if not isinstance(tasks, list):
                return False
            for task in tasks:
                if not isinstance(task, dict):
                    return False
                task_id = task.get("id")
                if task_id is not None and not isinstance(task_id, (str, int)):
                    return False

        return True

    def exists(self, mission_id: str) -> bool:
        return self._path(mission_id).exists()

    def clear(self, mission_id: str) -> None:
        self._path(mission_id).unlink(missing_ok=True)
