"""Execution sandbox policy primitives.

This module does not execute attacker-controlled commands. It produces an
immutable policy that a concrete Docker/container runtime can enforce. Keeping
policy separate from execution prevents an LLM from silently weakening the
runtime boundary.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SandboxPolicy:
    image: str = "nexus-strike/tool-runtime:latest"
    network: str = "none"
    read_only_root: bool = True
    no_new_privileges: bool = True
    drop_all_capabilities: bool = True
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    pids_limit: int = 128
    timeout_seconds: int = 300
    workdir: str = "/workspace"

    def docker_args(self) -> tuple[str, ...]:
        """Return conservative Docker flags for a trusted execution adapter."""
        if self.timeout_seconds <= 0 or self.pids_limit <= 0:
            raise ValueError("sandbox limits must be positive")
        if self.cpu_limit <= 0:
            raise ValueError("cpu_limit must be positive")
        return (
            "--network", self.network,
            "--read-only" if self.read_only_root else "--tmpfs", 
            "/tmp:rw,noexec,nosuid,size=64m" if self.read_only_root else "/tmp",
            "--security-opt", "no-new-privileges:true" if self.no_new_privileges else "seccomp=unconfined",
            "--cap-drop", "ALL" if self.drop_all_capabilities else "",
            "--memory", self.memory_limit,
            "--cpus", str(self.cpu_limit),
            "--pids-limit", str(self.pids_limit),
            "--workdir", self.workdir,
        )

    def validate(self) -> None:
        if self.network != "none":
            raise ValueError("tool sandbox must default to network=none")
        if not self.read_only_root:
            raise ValueError("tool sandbox requires a read-only root filesystem")
        if not self.no_new_privileges:
            raise ValueError("tool sandbox requires no-new-privileges")
        if not self.drop_all_capabilities:
            raise ValueError("tool sandbox requires all Linux capabilities dropped")
