#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering tool: Ghidra Analysis
Domain: reverse_engineering

Previously this claimed to be "Ghidra Analysis" but never invoked Ghidra at
all — just file-magic/hash inspection. That's genuinely useful, but the name
overclaimed the capability. Now: real detection of a local Ghidra install
(GHIDRA_INSTALL_DIR or analyzeHeadless on PATH) and a real, minimal headless
invocation when one is found; an honest "static analysis only, Ghidra not
detected" note when it isn't — never claims full disassembly happened when
it didn't.
"""
import hashlib
import os
import shutil
import tempfile

from nexus.tools.registry import tool_registry
from nexus.tools.docker_sandbox import run_subprocess_sandboxed
from nexus.tools.sandbox import SandboxError

_HEADLESS_TIMEOUT = 60
# A binary handed to a headless decompiler is, by construction, untrusted —
# a pathologically-crafted sample can be designed to blow up Ghidra's own
# analyzer's memory/CPU use, independent of any timeout. Enforced via
# nexus.tools.sandbox (real kernel rlimit on POSIX, real psutil watchdog on
# Windows) rather than trusting the target file to behave.
_GHIDRA_CPU_LIMIT_S = 55
_GHIDRA_MEMORY_LIMIT_MB = 2048


def _find_analyze_headless() -> str | None:
    """Locate Ghidra's headless analyzer script, if a Ghidra install is
    actually present. Checks GHIDRA_INSTALL_DIR first (the standard way
    Ghidra installs are located — its own docs recommend setting it), then
    falls back to whatever `analyzeHeadless`/`analyzeHeadless.bat` PATH
    resolution finds."""
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        for name in ("analyzeHeadless.bat", "analyzeHeadless"):
            candidate = os.path.join(install_dir, "support", name)
            if os.path.isfile(candidate):
                return candidate
    return shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")


def _run_headless_ghidra(headless_path: str, target: str) -> str:
    """Minimal real headless invocation: import the binary into a disposable
    throwaway project and let Ghidra's own analyzer run, capturing whatever
    summary it prints. This deliberately does not attempt a full
    scripted-decompilation pipeline (that's a much larger surface than a
    tool-registry check needs) — it's enough to prove genuine engagement
    with the real Ghidra toolchain rather than fabricating one."""
    with tempfile.TemporaryDirectory(prefix="nexus-ghidra-") as project_dir:
        cmd = [
            headless_path, project_dir, "nexus_strike_project",
            "-import", target, "-overwrite",
        ]
        # NEXUS_SANDBOX_MODE=docker note: this call site is wired for
        # container isolation the same way exploit_dev/fuzzing.py is, but
        # two things limit it in practice today, honestly documented rather
        # than silently glossed over: (1) nexus.tools.docker_sandbox's
        # auto-mount always mounts read-only, while Ghidra needs to WRITE
        # into project_dir — docker mode will currently fail closed with a
        # permission error rather than complete a real headless run; (2)
        # the default sandbox image doesn't bundle Ghidra itself, so even a
        # writable mount wouldn't be sufficient without a custom image. The
        # host-process path (the default, unaffected by this) is unchanged
        # and is what actually runs when a local Ghidra install is found.
        result = run_subprocess_sandboxed(
            cmd,
            timeout=_HEADLESS_TIMEOUT,
            cpu_seconds=_GHIDRA_CPU_LIMIT_S,
            memory_mb=_GHIDRA_MEMORY_LIMIT_MB,
        )
        output = result.stdout or ""
        return output[-2000:]  # tail — Ghidra's own analysis summary is at the end


def run(target: str, **kwargs) -> dict:
    """reverse_engineering tool: Ghidra Analysis"""
    findings = []
    try:
        if os.path.isfile(target):
            with open(target, "rb") as f:
                data = f.read()
            findings.append(f"File: {target}")
            findings.append(f"Size: {len(data)} bytes")
            findings.append(f"MD5: {hashlib.md5(data, usedforsecurity=False).hexdigest()}")
            findings.append(f"SHA256: {hashlib.sha256(data).hexdigest()}")
            if data[:4] == b"\x7fELF":
                findings.append("File type: ELF binary")
            elif data[:2] == b"MZ":
                findings.append("File type: PE (Windows) binary")
            else:
                findings.append(f"File type: unknown (magic: {data[:4].hex()})")

            headless_path = _find_analyze_headless()
            if headless_path:
                findings.append(f"Ghidra headless analyzer found: {headless_path}")
                try:
                    output = _run_headless_ghidra(headless_path, target)
                    findings.append("Ghidra headless analysis completed")
                    if output.strip():
                        findings.append(f"Ghidra analyzer output (tail): {output.strip()[-500:]}")
                except SandboxError as e:
                    if "resource limit" in str(e):
                        findings.append(
                            f"Ghidra headless analysis exceeded its CPU/memory limit "
                            f"({_GHIDRA_CPU_LIMIT_S}s CPU / {_GHIDRA_MEMORY_LIMIT_MB}MB) "
                            f"analyzing this sample — no disassembly results captured: {e}"
                        )
                    else:
                        findings.append(
                            f"Ghidra headless analysis exceeded {_HEADLESS_TIMEOUT}s timeout — "
                            f"no disassembly results captured"
                        )
                except Exception as e:
                    findings.append(f"Ghidra headless analysis failed to run: {e}")
            else:
                findings.append(
                    "Static magic-byte/hash analysis only — Ghidra not detected on this system "
                    "(no GHIDRA_INSTALL_DIR and no analyzeHeadless on PATH). "
                    "Full disassembly/decompilation was not performed."
                )
        else:
            findings.append(f"Target {target} is not a file")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "reverse_engineering.ghidra_analysis", "domain": "reverse_engineering", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("reverse_engineering.ghidra_analysis", run, metadata={
    "name": "reverse_engineering.ghidra_analysis",
    "domain": "reverse_engineering",
    "status": "completed",
    "description": "reverse_engineering tool: real headless Ghidra analysis when installed, honest static-only fallback otherwise",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
