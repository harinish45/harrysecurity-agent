"""
NEXUS-STRIKE Tool Registry
Central registry for all security tools across domains.
Supports registration, lookup, domain filtering, metadata, typed execution profiles,
and contract assurance.
"""
from typing import Callable, Dict, Any, List, Optional, Tuple

from nexus.tools.profile import ToolProfile, profile_from_metadata


class ToolRegistry:
    """Central registry for all security tools across all domains."""

    def __init__(self):
        self._tools: Dict[str, Callable] = {}
        self._metadata: Dict[str, dict] = {}
        self._profiles: Dict[str, ToolProfile] = {}

    def register(self, name: str, fn: Callable, metadata: Optional[dict] = None):
        """Register a tool by domain-qualified name."""
        self._tools[name] = fn
        effective = metadata or {
            "name": name,
            "domain": name.split(".")[0] if "." in name else "unknown",
            "status": "stub",
        }
        profile = profile_from_metadata(name, effective)
        self._profiles[name] = profile
        self._metadata[name] = {**effective, "profile": profile}

    def get(self, name: str) -> Callable:
        """Get a tool function by name."""
        if name not in self._tools:
            raise KeyError(
                f"Tool '{name}' not found. "
                f"Available tools: {', '.join(sorted(self._tools)[:10])}..."
            )
        return self._tools[name]

    def get_profile(self, name: str) -> ToolProfile:
        """Get the validated execution/performance contract for a tool."""
        if name not in self._profiles:
            raise KeyError(f"Tool '{name}' has no execution profile")
        return self._profiles[name]

    def list_tools(self) -> Dict[str, dict]:
        """List all registered tools with metadata."""
        return {k: self._metadata.get(k, {}) for k in sorted(self._tools)}

    def list_profiles(self) -> Dict[str, dict[str, object]]:
        """Return JSON-safe operational profiles for routing/scheduling UIs."""
        return {k: self._profiles[k].to_dict() for k in sorted(self._profiles)}

    def assurance_report(self):
        """Return a deterministic contract-health report for every registered tool."""
        from nexus.tools.assurance import ToolAssurance

        checks = ToolAssurance().audit(self._tools, self._profiles)
        return {
            "total": len(checks),
            "healthy": sum(check.healthy for check in checks),
            "unhealthy": sum(not check.healthy for check in checks),
            "checks": checks,
        }

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
# Domain grouping helpers
# =============================================================================

def get_tool_domains() -> list:
    """Return all unique tool domain names."""
    return tool_registry.get_domains()


def get_tools_by_domain() -> dict:
    """Return tools grouped by domain."""
    groups: dict = {}
    for name in sorted(tool_registry._tools):
        domain = name.split(".")[0] if "." in name else "unknown"
        groups.setdefault(domain, []).append(name)
    return groups


def get_tool_count_by_domain() -> dict:
    """Return tool count per domain."""
    return {domain: len(tools) for domain, tools in get_tools_by_domain().items()}
