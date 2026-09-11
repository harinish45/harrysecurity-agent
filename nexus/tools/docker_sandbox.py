"""Container-isolated subprocess execution — a second, independent
sandboxing layer alongside ``nexus.tools.sandbox``'s host-process rlimit/
watchdog enforcement, not a replacement for it.

``nexus.tools.sandbox.run_subprocess()`` bounds a child process's wall-clock
time, CPU time, and memory — real enforcement, but the child still shares
the host's filesystem, network, and kernel. For tools that run genuinely
untrusted input through an external binary (a fuzzer feeding mutated bytes
to a local executable, a decompiler importing an unknown sample), that's a
meaningfully larger attack surface than resource exhaustion alone: a
container escape is a much higher bar than a plain host process compromise,
and a container can be denied network access outright (``--network none``)
where a host process technically still has it even if a given tool doesn't
use it.

This module adds an **opt-in** ``NEXUS_SANDBOX_MODE=docker`` path
(``nexus.foundation.config.config.nexus_sandbox_mode``, default
``"process"`` — no behavior change for existing installs) that runs the
same command inside a disposable, network-isolated, resource-capped
container instead. It fails closed: if docker mode is requested but no
daemon is reachable, ``run_subprocess_sandboxed()`` raises rather than
silently falling back to the host-process path — a silent fallback here
would be a security regression happening invisibly.

Any host file path present as a command argument is auto-detected and
bind-mounted read-only into the container at a deterministic path, with the
argument rewritten to match, so a caller can pass the same command list it
would have passed to ``nexus.tools.sandbox.run_subprocess()`` unchanged.
"""
from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

from nexus.tools.sandbox import SandboxError, run_subprocess

DEFAULT_SANDBOX_IMAGE = "nexus-strike/tool-sandbox:latest"
_DAEMON_CHECK_TIMEOUT_S = 5
_MOUNT_ROOT = "/sandbox_input"


def docker_daemon_available() -> bool:
    """Real daemon-reachability check — ``shutil.which("docker")`` only
    proves the CLI binary exists, not that a daemon is actually listening
    (this dev machine has the Desktop CLI installed with the daemon
    stopped, which is exactly the case that check would miss). ``docker
    info`` talks to the daemon and fails fast if nothing answers."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=_DAEMON_CHECK_TIMEOUT_S,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _auto_mount_paths(cmd: list[str]) -> tuple[list[str], dict[str, str]]:
    """Scan ``cmd`` for arguments that are real, existing host file paths
    and rewrite them to point at a deterministic in-container mount.
    Returns ``(rewritten_cmd, {host_dir: container_dir})``. Mounting the
    *parent directory* (not the file itself) read-only means a tool that
    needs sibling files (e.g. a script importing a helper in the same
    directory) still finds them, at the cost of exposing that whole
    directory rather than just the one file — an accepted, documented
    tradeoff for a proof-of-integration scope, not a general-purpose
    minimal-exposure mounter."""
    rewritten: list[str] = []
    mounts: dict[str, str] = {}
    seen_dirs: dict[str, str] = {}
    for i, arg in enumerate(cmd):
        candidate = Path(arg)
        if not candidate.is_absolute() or not candidate.exists():
            rewritten.append(arg)
            continue
        host_dir = str(candidate.parent.resolve())
        if host_dir not in seen_dirs:
            container_dir = f"{_MOUNT_ROOT}_{len(seen_dirs)}"
            seen_dirs[host_dir] = container_dir
            mounts[host_dir] = container_dir
        container_path = f"{seen_dirs[host_dir]}/{candidate.name}"
        rewritten.append(container_path)
    return rewritten, mounts


def run_subprocess_in_container(
    cmd: list[str],
    *,
    image: str = DEFAULT_SANDBOX_IMAGE,
    timeout: float = 300,
    cpu_seconds: float | None = None,
    memory_mb: float | None = None,
    input: str | bytes | None = None,
    network: bool = False,
    extra_mounts: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run ``cmd`` inside a disposable container: no network by default,
    a read-only root filesystem, and CPU/memory limits enforced by the
    Docker daemon itself (a second, container-level ceiling on top of
    whatever the caller separately enforces in-process) — one `--network
    none` deny-all plus one `--memory`/`--cpus` pair, not a configurable
    policy surface.

    Raises ``SandboxError`` if no daemon is reachable (checked once,
    up front — never a silent fallback to unsandboxed host execution) or
    if the container itself times out / is killed for a resource
    violation, mirroring ``nexus.tools.sandbox.run_subprocess()``'s
    exception contract so callers can treat both paths identically.

    The *outer* ``docker run`` invocation is itself executed through
    ``nexus.tools.sandbox.run_subprocess()`` — reusing its proven
    whole-process-tree kill-on-timeout logic rather than re-implementing
    process supervision here. Docker's own `--rm` still guarantees
    container cleanup even if the client-side `docker run` call is killed
    before it returns.
    """
    if not cmd or not isinstance(cmd, list):
        raise SandboxError("cmd must be a non-empty list (no shell=True, ever)")
    if not docker_daemon_available():
        raise SandboxError(
            "NEXUS_SANDBOX_MODE=docker is set but no Docker daemon is reachable "
            "(`docker info` failed) — refusing to fall back to unsandboxed host "
            "execution. Start the Docker daemon, or unset NEXUS_SANDBOX_MODE to "
            "use the host-process sandbox instead."
        )

    rewritten_cmd, auto_mounts = _auto_mount_paths(cmd)
    all_mounts = {**auto_mounts, **(extra_mounts or {})}

    container_name = f"nexus-sandbox-{uuid.uuid4().hex[:8]}"
    docker_cmd = ["docker", "run", "--rm", "--name", container_name]
    docker_cmd += ["--network", "none"] if not network else []
    docker_cmd += ["--read-only", "--tmpfs", "/tmp"]
    if memory_mb is not None:
        docker_cmd += ["--memory", f"{int(memory_mb)}m", "--memory-swap", f"{int(memory_mb)}m"]
    if cpu_seconds is not None:
        # Docker has no direct "CPU-seconds" limit — `--cpus` caps the rate
        # (cores available), while the outer wall-clock `timeout` below
        # bounds duration. Together they bound total CPU-time similarly to
        # the host-process RLIMIT_CPU path, though not identically (a
        # single-threaded tool hitting the wall-clock timeout is bounded
        # the same either way; a multi-threaded one could still burn more
        # aggregate CPU-seconds than the host path would allow before
        # `--cpus` throttles it back down).
        docker_cmd += ["--cpus", "1"]
    for host_dir, container_dir in all_mounts.items():
        docker_cmd += ["-v", f"{host_dir}:{container_dir}:ro"]
    docker_cmd += [image] + rewritten_cmd

    try:
        result = run_subprocess(docker_cmd, timeout=timeout, input=input)
    except SandboxError:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=10)
        raise
    return result


def run_subprocess_sandboxed(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Dispatch to the container path when ``NEXUS_SANDBOX_MODE=docker``,
    otherwise the existing host-process path — the single place a tool
    call site needs to check to support both, matching this codebase's
    established one-choke-point pattern (``safe_urlopen``, ``ToolExecutor``).
    """
    from nexus.foundation.config import config

    if config.nexus_sandbox_mode == "docker":
        return run_subprocess_in_container(cmd, **kwargs)
    return run_subprocess(cmd, **kwargs)
