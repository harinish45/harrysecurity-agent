"""Sandboxed subprocess execution for tools/scripts that shell out.

Two problems this fixes, both found in the pattern used across the
codebase (``subprocess.Popen(cmd, env=dict(os.environ))`` with no
timeout):

1. **Full environment inheritance.** Every child process got every
   variable in the parent's environment — API keys, credentials, whatever
   else happened to be set — whether the child needed them or not
   (CWE-200-adjacent: unnecessary secret exposure to spawned tools).
2. **No enforced timeout, no real kill.** A stuck child process could hang
   a scan indefinitely; even where a ``timeout=`` was passed to
   ``subprocess.run``, that only raises in the parent — it doesn't
   reliably kill the whole process tree on Windows.

``run_subprocess()`` builds an explicit minimal environment (an allow-list
plus anything the caller opts in via ``env_extra``) and, on timeout, kills
the entire process group/tree rather than just the immediate child.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys

logger = logging.getLogger("nexus.sandbox")

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


def run_subprocess(
    cmd: list[str],
    *,
    timeout: float = 300,
    cwd: str | None = None,
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run ``cmd`` with a minimal environment and a real, whole-process-tree
    kill on timeout.

    Raises ``SandboxError`` (wrapping the original timeout) instead of
    letting ``subprocess.TimeoutExpired`` propagate, so callers get one
    exception type to handle regardless of platform.
    """
    if not cmd or not isinstance(cmd, list):
        raise SandboxError("cmd must be a non-empty list (no shell=True, ever)")

    env = _minimal_env(env_extra)
    popen_kwargs: dict = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True  # own process group via os.setsid

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd,
        env=env,
        **popen_kwargs,
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise SandboxError(f"Command exceeded timeout of {timeout}s: {' '.join(cmd)}")

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
