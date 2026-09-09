"""Cross-cutting platform control-plane primitives.

These contracts are intentionally dependency-light so every runtime, agent,
tool, API and UI layer can share the same safety and lifecycle semantics.
"""

from .cache import ExecutionCache
from .contracts import (
    CapabilityState,
    Evidence,
    ExecutionPolicy,
    MissionNode,
    Role,
    ToolCapability,
    TenantContext,
    execution_cache_key,
)
from .sandbox import SandboxPolicy

__all__ = [
    "CapabilityState",
    "Evidence",
    "ExecutionCache",
    "ExecutionPolicy",
    "MissionNode",
    "Role",
    "SandboxPolicy",
    "ToolCapability",
    "TenantContext",
    "execution_cache_key",
]
