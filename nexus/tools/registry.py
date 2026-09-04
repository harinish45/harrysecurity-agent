"""
NEXUS-STRIKE Tool Registry
Central registry for all 500+ security tools across 29 domains.
Supports registration, lookup, domain filtering, and metadata.
"""
from typing import Callable, Dict, Any, List, Optional, Tuple


class ToolRegistry:
    """Central registry for all security tools across all domains."""

    def __init__(self):
        self._tools: Dict[str, Callable] = {}
        self._metadata: Dict[str, dict] = {}

    def register(self, name: str, fn: Callable, metadata: Optional[dict] = None):
        """Register a tool by domain-qualified name (e.g., 'reconnaissance.subdomain_enum')."""
        self._tools[name] = fn
        self._metadata[name] = metadata or {
            "name": name,
            "domain": name.split(".")[0] if "." in name else "unknown",
            "status": "stub",
        }

    def get(self, name: str) -> Callable:
        """Get the raw tool function by name (bypasses guardrails).

        Internal use only — nexus.tools.executor.ToolExecutor.run() calls this
        to fetch the function it then runs behind the full guardrail chain,
        and tests use it to smoke-test tools directly. Agent and mission code
        must call `run()` below instead, so every tool invocation gets
        guardrail enforcement (scope/legal/rate/audit) — calling this
        directly from agent code skips all of that.
        """
        if name not in self._tools:
            raise KeyError(
                f"Tool '{name}' not found. "
                f"Available tools: {', '.join(sorted(self._tools)[:10])}..."
            )
        return self._tools[name]

    def run(self, name: str, target: str, **kwargs: Any) -> dict:
        """Execute a tool through the guardrailed ToolExecutor.

        This is the safe entrypoint for agents and orchestration code: unlike
        `get()`, it enforces InputGuard/ScopeGuard/LegalGuard/EscalationGuard/
        RateGuard/AuditGuard and normalizes the result to the canonical
        schema, exactly like a dashboard-triggered scan does.
        """
        from nexus.tools.executor import ToolExecutor

        return ToolExecutor().run(name, target=target, **kwargs)

    def list_tools(self) -> Dict[str, dict]:
        """List all registered tools with metadata."""
        return {k: self._metadata.get(k, {}) for k in sorted(self._tools)}

    def list_by_domain(self, domain: str) -> List[str]:
        """List all tools in a specific domain."""
        domain = domain.lower().strip()
        return sorted([k for k in self._tools if k.startswith(f"{domain}.")])

    def get_domains(self) -> List[str]:
        """Get all unique domains with registered tools."""
        domains = set()
        for name in self._tools:
            if "." in name:
                domains.add(name.split(".")[0])
        return sorted(domains)

    def count_by_domain(self) -> Dict[str, int]:
        """Get tool counts per domain."""
        counts = {}
        for name in self._tools:
            domain = name.split(".")[0] if "." in name else "unknown"
            counts[domain] = counts.get(domain, 0) + 1
        return counts

    @property
    def count(self) -> int:
        return len(self._tools)


# Global singleton
tool_registry = ToolRegistry()


def list_tools() -> List[Tuple[str, Callable]]:
    """
    Return an iterable of (tool_name, tool_func) tuples.
    Tests expect exactly two values per param.
    """
    return [(name, tool_registry.get(name)) for name in sorted(tool_registry._tools)]


# =============================================================================
# Domain grouping helpers (Enhancement Package)
# =============================================================================

def get_tool_domains() -> list:
    """Return all unique tool domain names."""
    return tool_registry.get_domains()


def get_tools_by_domain() -> dict:
    """Return tools grouped by domain (dict[domain, list[tool_name]])."""
    groups: dict = {}
    for name in sorted(tool_registry._tools):
        domain = name.split(".")[0] if "." in name else "unknown"
        groups.setdefault(domain, []).append(name)
    return groups


def get_tool_count_by_domain() -> dict:
    """Return tool count per domain."""
    return {domain: len(tools) for domain, tools in get_tools_by_domain().items()}