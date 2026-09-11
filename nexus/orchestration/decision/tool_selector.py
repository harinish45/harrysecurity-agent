"""Picks which tools represent a domain when only a handful can be run for a
phase — a heuristic ranking (broad-coverage tools first), not machine
learning. Replaces the previous `domain_tools[:3]` registration-order slice
that had no notion of which tools were actually useful first."""
from __future__ import annotations

from nexus.tools.registry import tool_registry

# Tool name fragments that tend to be cheap, broad, and useful early in an
# assessment (discovery/enumeration before deeper, narrower probes).
_PREFERRED_FRAGMENTS = (
    "recon", "discovery", "enum", "fingerprint", "scan", "detection", "assessment", "lookup",
)


class ToolSelector:
    @staticmethod
    def select(domain: str, limit: int = 3) -> list[str]:
        candidates = tool_registry.list_by_domain(domain)
        if not candidates:
            return []

        def _rank(name: str) -> tuple[int, str]:
            leaf = name.split(".", 1)[-1]
            preferred = any(frag in leaf for frag in _PREFERRED_FRAGMENTS)
            return (0 if preferred else 1, name)

        return sorted(candidates, key=_rank)[:limit]
