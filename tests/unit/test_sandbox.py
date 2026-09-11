import sys
import time

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


def test_run_subprocess_passes_stdin_input():
    result = run_subprocess(
        [sys.executable, "-c", "import sys; data = sys.stdin.read(); print(f'GOT:{data}')"],
        timeout=10,
        input="payload-via-stdin",
    )
    assert "GOT:payload-via-stdin" in result.stdout


def test_run_subprocess_stdin_is_devnull_when_no_input_given():
    """Default stdin must not be inherited from this process — a child
    blocking on unexpected stdin data is a hang risk this module is
    specifically supposed to prevent."""
    result = run_subprocess(
        [sys.executable, "-c", "import sys; data = sys.stdin.read(); print(f'READ:{len(data)}bytes')"],
        timeout=10,
    )
    assert "READ:0bytes" in result.stdout


def test_run_subprocess_timeout_actually_kills_the_process(tmp_path):
    """Not just 'raises SandboxError' — confirm the child is genuinely
    dead afterward, not orphaned/hung in the background. A stray marker
    file the child would only create AFTER the point we kill it at proves
    it never got there."""
    marker = tmp_path / "should_not_exist.txt"
    script = (
        "import time, pathlib\n"
        "time.sleep(5)\n"
        f"pathlib.Path(r'{marker}').write_text('reached')\n"
    )
    with pytest.raises(SandboxError):
        run_subprocess([sys.executable, "-c", script], timeout=0.5)
    time.sleep(1)  # give a (hypothetically) un-killed process time to reach the write
    assert not marker.exists(), "child process was not actually killed — it ran past the timeout point"


# ── Resource limits (cpu_seconds / memory_mb) ────────────────────────────
# CPU-time enforcement is real and live-testable on both platforms (a
# tight busy-loop reliably burns real CPU time within a short window).
# Memory enforcement is real on both platforms too, but this test suite
# only asserts the CPU path directly — matching this module's own
# docstring, POSIX enforcement is a hard kernel rlimit (verified by the
# SIGXCPU/RLIMIT_AS code paths below on non-Windows CI) while Windows uses
# the psutil watchdog (verified by the dedicated watchdog test).

def _busy_loop_script(seconds: float) -> str:
    return f"import time\nend = time.time() + {seconds}\nwhile time.time() < end:\n    pass\n"


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_CPU/RLIMIT_AS are POSIX-only; Windows path covered by test_resource_watchdog_kills_on_memory_overshoot")
def test_posix_cpu_rlimit_is_actually_enforced():
    """A real, kernel-enforced CPU-time ceiling — not a polling check.
    A tight busy-loop that would otherwise run for 5s must be killed
    well before that once it burns more CPU time than the limit."""
    started = time.monotonic()
    with pytest.raises(SandboxError):
        run_subprocess(
            [sys.executable, "-c", _busy_loop_script(5)],
            timeout=10,
            cpu_seconds=1,
        )
    elapsed = time.monotonic() - started
    assert elapsed < 5, f"CPU rlimit did not cut the busy-loop short (took {elapsed:.1f}s)"


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_AS is POSIX-only")
def test_posix_memory_rlimit_is_actually_enforced():
    """A process that tries to allocate well past its RLIMIT_AS ceiling
    must fail to allocate (MemoryError in the child) rather than being
    allowed to consume unbounded host memory."""
    script = (
        "try:\n"
        "    x = bytearray(500 * 1024 * 1024)  # 500MB, well past the 64MB limit below\n"
        "    print('ALLOCATED')\n"
        "except MemoryError:\n"
        "    print('BLOCKED')\n"
    )
    result = run_subprocess([sys.executable, "-c", script], timeout=10, memory_mb=64)
    assert "ALLOCATED" not in result.stdout


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="_ResourceWatchdog is only started on win32 (nexus/tools/sandbox.py's "
    "run_subprocess gates it behind sys.platform == 'win32'); on POSIX, memory_mb "
    "is enforced by the real RLIMIT_AS kernel rlimit instead (covered by "
    "test_posix_memory_rlimit_is_actually_enforced above), so this code path is "
    "never reached there and the process would just crash with an uncaught "
    "MemoryError in the child rather than run_subprocess raising SandboxError.",
)
def test_resource_watchdog_kills_on_memory_overshoot():
    """Real enforcement path used on Windows: a process that allocates and
    holds well past memory_mb must be killed by the watchdog, not allowed
    to run to completion."""
    pytest.importorskip("psutil")
    script = (
        "import time\n"
        "x = bytearray(300 * 1024 * 1024)  # 300MB, held so the watchdog has time to sample it\n"
        "time.sleep(10)\n"
    )
    with pytest.raises(SandboxError, match="resource limit"):
        run_subprocess([sys.executable, "-c", script], timeout=15, memory_mb=64)
