"""Behavioral tests for digital_twin_agent — mocks Docker entirely (no live
daemon required/assumed; this machine's Docker CLI is present but the
daemon isn't running, so none of this can be exercised for real here)."""
import subprocess

import pytest

from nexus.agents.offensive.digital_twin_agent import DigitalTwinAgent


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.mark.asyncio
async def test_unavailable_when_docker_not_on_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest", check_command=["true"])
    assert result["status"] == "unavailable"
    assert "docker" in result["error"].lower()
    assert "path" in result["error"].lower()


@pytest.mark.asyncio
async def test_unavailable_when_image_or_check_command_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    result = await DigitalTwinAgent().run("rehearse", target="x")
    assert result["status"] == "unavailable"
    assert "image" in result["error"] or "check_command" in result["error"]

    result2 = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest")
    assert result2["status"] == "unavailable"


@pytest.mark.asyncio
async def test_unavailable_when_check_command_is_a_string(monkeypatch):
    """subprocess.run(check_command, shell=False, ...) requires a list/tuple
    of args, matching every other subprocess.run() call in this codebase
    (installer_agent.py, pdf_export.py, sandbox.py, wpa_test.py). A shell
    string here would make Python try to run a program literally named
    after the whole string and fail with a cryptic OS error — this should
    be caught up front with a clear message instead."""
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")
    result = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest",
                                          check_command="curl -s http://twin:8080/")
    assert result["status"] == "unavailable"
    assert "list" in result["summary"].lower()


@pytest.mark.asyncio
async def test_reproduced_true_and_cleanup_runs_on_success(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            return _FakeCompletedProcess(returncode=0)
        if cmd[:2] == ["docker", "rm"]:
            return _FakeCompletedProcess(returncode=0)
        # the check_command probe
        return _FakeCompletedProcess(returncode=0, stdout="vulnerable!", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest",
                                          check_command=["curl", "-s", "http://twin:8080/"])

    assert result["status"] == "completed"
    assert result["metadata"]["reproduced"] is True
    assert result["metadata"]["stdout"] == "vulnerable!"

    # docker run, the probe, and docker rm -f all happened, in that order,
    # and the rm targeted the same container name docker run created.
    assert calls[0][:2] == ["docker", "run"]
    assert calls[1] == ["curl", "-s", "http://twin:8080/"]
    assert calls[2][:2] == ["docker", "rm"]
    started_name = calls[0][calls[0].index("--name") + 1]
    removed_name = calls[2][-1]
    assert started_name == removed_name
    assert started_name.startswith("nexus-twin-")


@pytest.mark.asyncio
async def test_reproduced_false_when_check_command_exits_nonzero(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "run"]:
            return _FakeCompletedProcess(returncode=0)
        if cmd[:2] == ["docker", "rm"]:
            return _FakeCompletedProcess(returncode=0)
        return _FakeCompletedProcess(returncode=1, stdout="", stderr="404 not found")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest", check_command=["curl", "-s", "x"])

    assert result["status"] == "completed"
    assert result["metadata"]["reproduced"] is False
    assert result["metadata"]["stderr"] == "404 not found"


@pytest.mark.asyncio
async def test_failed_when_docker_run_itself_fails(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        raise subprocess.CalledProcessError(returncode=1, cmd=cmd)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest", check_command=["true"])

    assert result["status"] == "failed"
    assert "foo:latest" in result["summary"]
    # No container ever started — nothing else should have been attempted
    # (no probe run, no cleanup rm).
    assert len(calls) == 1
    assert calls[0][:2] == ["docker", "run"]


@pytest.mark.asyncio
async def test_failed_when_docker_run_times_out(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=60)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest", check_command=["true"])

    assert result["status"] == "failed"


@pytest.mark.asyncio
async def test_cleanup_runs_even_when_probe_raises(monkeypatch):
    """If check_command itself raises (bad binary, permissions, etc.), the
    `finally` block must still tear the container down — otherwise a
    disposable twin leaks every time the probe command is broken."""
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            return _FakeCompletedProcess(returncode=0)
        if cmd[:2] == ["docker", "rm"]:
            return _FakeCompletedProcess(returncode=0)
        raise FileNotFoundError("no such file: not-a-real-binary")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = await DigitalTwinAgent().run("rehearse", target="x", image="foo:latest",
                                          check_command=["not-a-real-binary"])

    assert result["status"] == "completed"
    assert result["metadata"]["reproduced"] is False
    assert "no such file" in result["metadata"]["stderr"]
    # docker run, the failed probe, and the cleanup rm all ran.
    assert len(calls) == 3
    assert calls[-1][:2] == ["docker", "rm"]
