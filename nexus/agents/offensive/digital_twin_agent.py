"""Best-effort disposable-twin rehearsal before a risky exploit is flagged
safe to report against a live/production target.

This is real infrastructure (spin up a containerized clone of the
fingerprinted service, rehearse against it, tear it down), but it hard-
depends on a local Docker daemon. When Docker isn't available this agent
returns ``STATUS_UNAVAILABLE`` with a clear reason rather than silently
skipping or pretending the rehearsal happened — a fabricated "verified safe"
result here would be worse than not having the feature at all. When Docker
*is* available, it does a real, minimal rehearsal: pull the fingerprinted
image, start it disposable/isolated, run the caller-supplied check command
against it, tear it down, and report whether the check reproduced there.
"""
from __future__ import annotations

import shutil
import subprocess
import uuid

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_UNAVAILABLE, STATUS_FAILED, tool_result

_DEFAULT_TIMEOUT = 60


class DigitalTwinAgent(BaseAgent):
    name = "digital_twin_agent"
    description = "offensive agent that rehearses an exploit against a disposable twin container before it is reported"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        image = kwargs.get("image")
        check_command = kwargs.get("check_command")

        if not shutil.which("docker"):
            return tool_result(
                self.name, target or "unknown",
                status=STATUS_UNAVAILABLE,
                summary="Digital-twin rehearsal requires a local Docker daemon, which is not available here",
                error="docker executable not found on PATH",
            )
        if not image or not check_command:
            return tool_result(
                self.name, target or "unknown",
                status=STATUS_UNAVAILABLE,
                summary="Digital-twin rehearsal needs a fingerprinted image and a check_command to run against it",
                error="missing 'image' or 'check_command'",
            )

        container_name = f"nexus-twin-{uuid.uuid4().hex[:8]}"
        try:
            subprocess.run(
                ["docker", "run", "-d", "--rm", "--name", container_name, image],
                capture_output=True, timeout=_DEFAULT_TIMEOUT, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            return tool_result(
                self.name, target or "unknown",
                status=STATUS_FAILED,
                summary=f"Failed to start digital twin from image {image}",
                error=str(exc),
            )

        try:
            probe = subprocess.run(
                check_command, shell=False, capture_output=True, text=True, timeout=_DEFAULT_TIMEOUT,
            )
            reproduced = probe.returncode == 0
        except (subprocess.SubprocessError, OSError) as exc:
            reproduced = False
            probe = None
            probe_error = str(exc)
        else:
            probe_error = None
        finally:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=_DEFAULT_TIMEOUT)

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Digital-twin rehearsal against {image}: "
                    f"{'reproduced' if reproduced else 'did not reproduce'}",
            metadata={
                "image": image,
                "reproduced": reproduced,
                "stdout": (probe.stdout[:2000] if probe else ""),
                "stderr": (probe.stderr[:2000] if probe else probe_error or ""),
            },
        )
