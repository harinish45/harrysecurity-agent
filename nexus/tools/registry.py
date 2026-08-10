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
        """Get a tool function by name."""
        if name not in self._tools:
            raise KeyError(
                f"Tool '{name}' not found. "
                f"Available tools: {', '.join(sorted(self._tools)[:10])}..."
            )
        return self._tools[name]

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