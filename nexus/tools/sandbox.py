"""Sandboxed subprocess execution for tools/scripts that shell out.

Three problems this fixes, all found in the pattern used across the
codebase (``subprocess.Popen(cmd, env=dict(os.environ))`` with no timeout
and no resource ceiling):

1. **Full environment inheritance.** Every child process got every
   variable in the parent's environment — API keys, credentials, whatever
   else happened to be set — whether the child needed them or not
   (CWE-200-adjacent: unnecessary secret exposure to spawned tools).
2. **No enforced timeout, no real kill.** A stuck child process could hang
   a scan indefinitely; even where a ``timeout=`` was passed to
   ``subprocess.run``, that only raises in the parent — it doesn't
   reliably kill the whole process tree on Windows.
3. **No resource ceiling.** A tool that shells out to an external
   binary against attacker-influenced input (fuzzing a local executable,
   decompiling an untrusted sample) had no defense against that child
   process consuming unbounded CPU or memory well within its wall-clock
   timeout — a resource-exhaustion risk to the host running NEXUS-STRIKE
   itself, not just a hang.

``run_subprocess()`` builds an explicit minimal environment (an allow-list
plus anything the caller opts in via ``env_extra``), enforces optional
``cpu_seconds``/``memory_mb`` ceilings, and on timeout/limit-violation
kills the entire process group/tree rather than just the immediate child.

Resource-limit enforcement is platform-dependent:
  - **POSIX** (Linux/macOS): real, kernel-enforced ``RLIMIT_CPU``/
    ``RLIMIT_AS`` set in the child via ``preexec_fn`` before ``exec`` —
    the kernel itself blocks the overshoot (a further ``malloc`` fails,
    CPU-time signal fires), not a race against a polling check.
  - **Windows**: no ``resource`` module / rlimit equivalent in the
    stdlib. Falls back to a ``psutil``-based polling watchdog thread that
    samples the child's (and its descendants') RSS/CPU time and kills the
    tree on overshoot — real enforcement, but reactive (bounded by the
    poll interval) rather than a hard kernel ceiling.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard requirement (requirements.txt) in normal installs
    psutil = None

if sys.platform != "win32":
    import resource
else:  # pragma: no cover - Windows has no `resource` module
    resource = None

logger = logging.getLogger("nexus.sandbox")

_WATCHDOG_POLL_INTERVAL_S = 0.5

# Variables a child process plausibly needs to run at all. Deliberately
# does NOT include secrets/credentials/proxy config — a tool that needs
# those should receive them explicitly via env_extra, not by osmosis.
_ENV_ALLOWLIST = {"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "HOME",
                   "USERPROFILE", "LANG", "LC_ALL", "TZ", "NEXUS_ENV", "NEXUS_LOG_LEVEL"}


class SandboxError(Exception):
    pass


def _minimal_env(env_extra: dict[str, str] | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}
    if env_extra:
        env.update(env_extra)
    return env


def _posix_rlimit_preexec(cpu_seconds: float | None, memory_mb: float | None):
    """Build a ``preexec_fn`` that sets real kernel-enforced rlimits in the
    child before ``exec`` — runs in the forked child, before the target
    binary replaces it, so this is unconditionally applied to whatever the
    child (and anything it execs) does. POSIX-only; never used on Windows."""
    def _apply() -> None:
        if cpu_seconds is not None:
            hard_cpu = max(int(cpu_seconds) + 1, 1)  # SIGXCPU soft limit, SIGKILL a beat later
            resource.setrlimit(resource.RLIMIT_CPU, (int(cpu_seconds), hard_cpu))
        if memory_mb is not None:
            mem_bytes = int(memory_mb * 1024 * 1024)
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    return _apply


class _ResourceWatchdog:
    """Windows fallback for resource-limit enforcement: no `resource`
    module / rlimit equivalent exists in the stdlib there, so this polls
    the child (and its descendants, since a spawned tool may itself fork
    further children) via psutil and kills the whole tree on overshoot.
    Real enforcement — verified live in this module's own tests — but
    reactive (bounded by `_WATCHDOG_POLL_INTERVAL_S`), not a hard kernel
    ceiling like the POSIX preexec_fn path."""

    def __init__(self, proc: subprocess.Popen, *, cpu_seconds: float | None, memory_mb: float | None):
        self._proc = proc
        self._cpu_seconds = cpu_seconds
        self._memory_bytes = int(memory_mb * 1024 * 1024) if memory_mb is not None else None
        self._violation: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if psutil is None or (self._cpu_seconds is None and self._memory_bytes is None):
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=_WATCHDOG_POLL_INTERVAL_S * 2)

    @property
    def violation(self) -> str | None:
        return self._violation

    def _run(self) -> None:
        try:
            parent = psutil.Process(self._proc.pid)
        except psutil.NoSuchProcess:  # pragma: no cover - process exited before we could attach
            return
        while not self._stop.wait(_WATCHDOG_POLL_INTERVAL_S):
            try:
                procs = [parent, *parent.children(recursive=True)]
                total_rss = 0
                total_cpu = 0.0
                for p in procs:
                    try:
                        total_rss += p.memory_info().rss
                        total_cpu += sum(p.cpu_times()[:2])  # user + system
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except psutil.NoSuchProcess:  # pragma: no cover - process exited mid-poll
                return
            if self._memory_bytes is not None and total_rss > self._memory_bytes:
                self._violation = f"memory usage {total_rss / 1024 / 1024:.1f}MB exceeded limit {self._memory_bytes / 1024 / 1024:.1f}MB"
                _kill_tree(self._proc)
                return
            if self._cpu_seconds is not None and total_cpu > self._cpu_seconds:
                self._violation = f"CPU time {total_cpu:.1f}s exceeded limit {self._cpu_seconds:.1f}s"
                _kill_tree(self._proc)
                return


def run_subprocess(
    cmd: list[str],
    *,
    timeout: float = 300,
    cwd: str | None = None,
    env_extra: dict[str, str] | None = None,
    cpu_seconds: float | None = None,
    memory_mb: float | None = None,
    input: str | bytes | None = None,
) -> subprocess.CompletedProcess:
    """Run ``cmd`` with a minimal environment, a real whole-process-tree
    kill on timeout, and optional CPU-time/memory ceilings.

    ``cpu_seconds``/``memory_mb``, when set, are enforced by a real kernel
    rlimit on POSIX and a real (polling) psutil watchdog on Windows — see
    the module docstring for the platform difference. Both are ``None`` by
    default (no change to existing callers' behavior).

    ``input``, when given, is written to the child's stdin (for tools like
    a mutation-based fuzzer that feed payloads via stdin rather than argv).
    When omitted, stdin is ``DEVNULL`` rather than inherited from this
    process — a child tool blocking on / reading unexpected data from
    NEXUS-STRIKE's own stdin is not a behavior any caller has ever
    depended on, and DEVNULL is the safer default.

    Raises ``SandboxError`` (wrapping the original timeout or resource
    violation) instead of letting ``subprocess.TimeoutExpired`` propagate,
    so callers get one exception type to handle regardless of platform.
    """
    if not cmd or not isinstance(cmd, list):
        raise SandboxError("cmd must be a non-empty list (no shell=True, ever)")

    env = _minimal_env(env_extra)
    popen_kwargs: dict = {}
    watchdog: _ResourceWatchdog | None = None
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True  # own process group via os.setsid
        if cpu_seconds is not None or memory_mb is not None:
            popen_kwargs["preexec_fn"] = _posix_rlimit_preexec(cpu_seconds, memory_mb)

    text_mode = not isinstance(input, bytes)
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=text_mode,
        cwd=cwd,
        env=env,
        **popen_kwargs,
    )

    if sys.platform == "win32" and (cpu_seconds is not None or memory_mb is not None):
        watchdog = _ResourceWatchdog(proc, cpu_seconds=cpu_seconds, memory_mb=memory_mb)
        watchdog.start()

    try:
        stdout, _ = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        if watchdog is not None:
            watchdog.stop()
        _kill_tree(proc)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise SandboxError(f"Command exceeded timeout of {timeout}s: {' '.join(cmd)}")
    finally:
        if watchdog is not None:
            watchdog.stop()

    if watchdog is not None and watchdog.violation is not None:
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise SandboxError(f"Command exceeded resource limit: {watchdog.violation}: {' '.join(cmd)}")

    if sys.platform != "win32" and proc.returncode is not None and proc.returncode < 0:
        sig = -proc.returncode
        if resource is not None and cpu_seconds is not None and sig == 24:  # SIGXCPU
            raise SandboxError(f"Command exceeded CPU-time limit of {cpu_seconds}s (SIGXCPU): {' '.join(cmd)}")
        if memory_mb is not None and sig == 9:  # SIGKILL — RLIMIT_AS overshoot is one possible cause
            logger.warning("Command %s was SIGKILLed; may be a memory_mb=%.0fMB rlimit violation", cmd, memory_mb)

    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, None)


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the whole process tree, not just the immediate child — a
    plain proc.kill() leaves grandchildren (e.g. a shell-spawned scanner)
    running after "timeout"."""
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=10,
            )
        else:
            os.killpg(os.getpgid(proc.pid), 9)  # SIGKILL the whole group
    except Exception:  # pragma: no cover - best-effort cleanup
        logger.warning("Failed to kill process tree for pid %s", proc.pid, exc_info=True)
        try:
            proc.kill()
        except Exception:
            pass
