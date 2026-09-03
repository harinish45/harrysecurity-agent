import sys

import pytest

from nexus.tools.sandbox import SandboxError, run_subprocess


def test_run_subprocess_captures_stdout():
    result = run_subprocess([sys.executable, "-c", "print('hello-from-sandbox')"], timeout=10)
    assert result.returncode == 0
    assert "hello-from-sandbox" in result.stdout


def test_run_subprocess_captures_nonzero_exit():
    result = run_subprocess([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=10)
    assert result.returncode == 3


def test_run_subprocess_rejects_empty_command():
    with pytest.raises(SandboxError):
        run_subprocess([], timeout=10)


def test_run_subprocess_rejects_non_list_command():
    with pytest.raises(SandboxError):
        run_subprocess("not-a-list", timeout=10)  # type: ignore[arg-type]


def test_run_subprocess_does_not_inherit_arbitrary_env(monkeypatch):
    monkeypatch.setenv("NEXUS_SANDBOX_TEST_SECRET", "should-not-leak")
    result = run_subprocess(
        [sys.executable, "-c", "import os; print(os.environ.get('NEXUS_SANDBOX_TEST_SECRET', 'ABSENT'))"],
        timeout=10,
    )
    assert "ABSENT" in result.stdout


def test_run_subprocess_env_extra_is_passed_through():
    result = run_subprocess(
        [sys.executable, "-c", "import os; print(os.environ.get('NEXUS_SANDBOX_EXTRA', 'MISSING'))"],
        timeout=10,
        env_extra={"NEXUS_SANDBOX_EXTRA": "present-value"},
    )
    assert "present-value" in result.stdout


def test_run_subprocess_timeout_raises_sandbox_error():
    with pytest.raises(SandboxError):
        run_subprocess([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
