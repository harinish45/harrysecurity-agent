"""nexus/tools/docker_sandbox.py — a second, container-level isolation
layer alongside nexus/tools/sandbox.py's host-process rlimit/watchdog
enforcement, opt-in via NEXUS_SANDBOX_MODE=docker.

This dev machine has the Docker Desktop CLI installed but the daemon is
NOT running (`docker info` genuinely fails here, confirmed live) — so
these tests split cleanly into two groups:
  - REAL, live-verified: daemon-unreachable detection, the fail-closed
    SandboxError path, the auto-mount path-rewriting logic (pure Python,
    no daemon needed), and the exact `docker run` command construction
    (mocked at the outer run_subprocess() call so no daemon is touched).
  - NOT verifiable here: an actual container executing and returning
    real output — that needs a live daemon this environment doesn't have.
    No test in this file claims that path works; it's exercised only via
    mocks that assert command construction, not actual execution.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from nexus.foundation.config import config
from nexus.tools.docker_sandbox import (
    DEFAULT_SANDBOX_IMAGE,
    _auto_mount_paths,
    docker_daemon_available,
    run_subprocess_in_container,
    run_subprocess_sandboxed,
)
from nexus.tools.sandbox import SandboxError


# ── docker_daemon_available() — real, live on this machine ─────────────

def test_daemon_unavailable_is_correctly_detected_live():
    """Real live check against this actual machine's Docker installation
    (CLI present, daemon stopped) — must report False, not crash, and
    not falsely report True."""
    assert docker_daemon_available() is False


def test_daemon_check_handles_missing_docker_cli_gracefully():
    with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
        assert docker_daemon_available() is False


def test_daemon_check_handles_hung_daemon_gracefully():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["docker", "info"], timeout=5)):
        assert docker_daemon_available() is False


def test_daemon_check_true_when_docker_info_succeeds():
    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        assert docker_daemon_available() is True


# ── Fail-closed: real, live-verified on this machine (no daemon) ───────

def test_run_subprocess_sandboxed_docker_mode_fails_closed_when_no_daemon(monkeypatch):
    """The core safety property: NEXUS_SANDBOX_MODE=docker with no
    reachable daemon must raise, never silently execute on the host."""
    monkeypatch.setattr(config, "nexus_sandbox_mode", "docker")
    with pytest.raises(SandboxError, match="no Docker daemon is reachable"):
        run_subprocess_sandboxed(["echo", "hi"])


def test_run_subprocess_in_container_fails_closed_when_no_daemon():
    with pytest.raises(SandboxError, match="no Docker daemon is reachable"):
        run_subprocess_in_container(["echo", "hi"])


def test_run_subprocess_in_container_rejects_empty_cmd():
    with pytest.raises(SandboxError, match="non-empty list"):
        run_subprocess_in_container([])


# ── Dispatch: process mode is the untouched default ─────────────────────

def test_run_subprocess_sandboxed_defaults_to_process_mode(monkeypatch):
    monkeypatch.setattr(config, "nexus_sandbox_mode", "process")
    with patch("nexus.tools.docker_sandbox.run_subprocess") as mock_host_run:
        mock_host_run.return_value = subprocess.CompletedProcess(["echo"], 0, "hi", None)
        result = run_subprocess_sandboxed(["echo", "hi"])
    mock_host_run.assert_called_once()
    assert result.returncode == 0


def test_run_subprocess_sandboxed_docker_mode_routes_to_container(monkeypatch):
    monkeypatch.setattr(config, "nexus_sandbox_mode", "docker")
    with patch("nexus.tools.docker_sandbox.run_subprocess_in_container") as mock_container_run:
        mock_container_run.return_value = subprocess.CompletedProcess(["echo"], 0, "hi", None)
        run_subprocess_sandboxed(["echo", "hi"], timeout=42)
    mock_container_run.assert_called_once_with(["echo", "hi"], timeout=42)


# ── _auto_mount_paths() — pure logic, real filesystem, no daemon needed ─

def test_auto_mount_rewrites_real_existing_file_path(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00\x01\x02")

    rewritten, mounts = _auto_mount_paths([str(target), "-import", "-overwrite"])

    host_dir = str(tmp_path.resolve())
    assert host_dir in mounts
    container_dir = mounts[host_dir]
    assert rewritten[0] == f"{container_dir}/sample.bin"
    assert rewritten[1:] == ["-import", "-overwrite"]


def test_auto_mount_leaves_nonexistent_and_relative_args_untouched():
    rewritten, mounts = _auto_mount_paths(["-import", "relative/path", "/nonexistent/file/xyz"])
    assert rewritten == ["-import", "relative/path", "/nonexistent/file/xyz"]
    assert mounts == {}


def test_auto_mount_dedupes_multiple_files_in_same_directory(tmp_path):
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(b"a")
    f2.write_bytes(b"b")

    rewritten, mounts = _auto_mount_paths([str(f1), str(f2)])

    assert len(mounts) == 1  # one directory, one mount, not two
    container_dir = next(iter(mounts.values()))
    assert rewritten[0] == f"{container_dir}/a.bin"
    assert rewritten[1] == f"{container_dir}/b.bin"


def test_auto_mount_gives_separate_mounts_for_separate_directories(tmp_path):
    dir1 = tmp_path / "d1"
    dir2 = tmp_path / "d2"
    dir1.mkdir()
    dir2.mkdir()
    f1 = dir1 / "a.bin"
    f2 = dir2 / "b.bin"
    f1.write_bytes(b"a")
    f2.write_bytes(b"b")

    rewritten, mounts = _auto_mount_paths([str(f1), str(f2)])

    assert len(mounts) == 2
    assert rewritten[0] != rewritten[1].rsplit("/", 1)[0] + "/" + rewritten[0].rsplit("/", 1)[1]


# ── docker run command construction — mocked at the outer call, real flags ─

def test_container_command_has_network_isolation_by_default(tmp_path):
    with patch("nexus.tools.docker_sandbox.docker_daemon_available", return_value=True), \
         patch("nexus.tools.docker_sandbox.run_subprocess") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", None)
        run_subprocess_in_container(["echo", "hi"])

    called_cmd = mock_run.call_args[0][0]
    assert "--network" in called_cmd
    assert called_cmd[called_cmd.index("--network") + 1] == "none"
    assert "--read-only" in called_cmd
    assert "--rm" in called_cmd
    assert DEFAULT_SANDBOX_IMAGE in called_cmd


def test_container_command_omits_network_isolation_when_explicitly_requested():
    with patch("nexus.tools.docker_sandbox.docker_daemon_available", return_value=True), \
         patch("nexus.tools.docker_sandbox.run_subprocess") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", None)
        run_subprocess_in_container(["echo", "hi"], network=True)

    called_cmd = mock_run.call_args[0][0]
    assert "--network" not in called_cmd


def test_container_command_applies_memory_and_cpu_limits():
    with patch("nexus.tools.docker_sandbox.docker_daemon_available", return_value=True), \
         patch("nexus.tools.docker_sandbox.run_subprocess") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", None)
        run_subprocess_in_container(["echo", "hi"], memory_mb=256, cpu_seconds=30)

    called_cmd = mock_run.call_args[0][0]
    assert "--memory" in called_cmd
    assert called_cmd[called_cmd.index("--memory") + 1] == "256m"
    assert "--cpus" in called_cmd


def test_container_command_mounts_real_host_file_readonly(tmp_path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")

    with patch("nexus.tools.docker_sandbox.docker_daemon_available", return_value=True), \
         patch("nexus.tools.docker_sandbox.run_subprocess") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", None)
        run_subprocess_in_container([str(target), "-analyze"])

    called_cmd = mock_run.call_args[0][0]
    mount_flags = [called_cmd[i + 1] for i, a in enumerate(called_cmd) if a == "-v"]
    assert len(mount_flags) == 1
    assert mount_flags[0].endswith(":ro")
    assert str(tmp_path.resolve()) in mount_flags[0]
    # the rewritten in-container path (not the host path) reaches the image
    assert str(target) not in called_cmd[called_cmd.index(DEFAULT_SANDBOX_IMAGE) + 1]


def test_container_cleanup_attempted_on_timeout(tmp_path):
    with patch("nexus.tools.docker_sandbox.docker_daemon_available", return_value=True), \
         patch("nexus.tools.docker_sandbox.run_subprocess", side_effect=SandboxError("timed out")), \
         patch("subprocess.run") as mock_cleanup:
        with pytest.raises(SandboxError):
            run_subprocess_in_container(["echo", "hi"])

    cleanup_cmd = mock_cleanup.call_args[0][0]
    assert cleanup_cmd[:3] == ["docker", "rm", "-f"]
