"""
Class-based Skill Registry for NEXUS-STRIKE (Enhancement Package).

Separate from the existing `skills_registry` (functional registry in registry.py).
This registry uses class-based skills that inherit from base.Skill.
"""
from typing import Dict, List, Type

from .base import Skill


class SkillRegistry:
    """Central registry for class-based security skills."""

    def __init__(self):
        self._skills: Dict[str, Type[Skill]] = {}
        self._metadata: Dict[str, dict] = {}

    def register(self, name: str, skill_class: Type[Skill], metadata: dict = None):
        """Register a skill class with optional metadata."""
        self._skills[name] = skill_class
        self._metadata[name] = metadata or {
            "name": name,
            "category": getattr(skill_class, "category", "unknown"),
            "description": getattr(skill_class, "description", ""),
        }

    def get(self, name: str) -> Type[Skill]:
        """Get a skill class by name."""
        if name not in self._skills:
            raise KeyError(f"Skill '{name}' not found")
        return self._skills[name]

    def list_all(self) -> List[dict]:
        """Return all registered skills as metadata dicts."""
        return [
            {
                "name": name,
                "category": self._metadata[name].get("category", "unknown"),
                "description": self._metadata[name].get("description", ""),
            }
            for name in sorted(self._skills)
        ]

    def list_by_category(self, category: str) -> List[str]:
        """Return skill names in a specific category."""
        return [
            name for name, meta in self._metadata.items()
            if meta.get("category") == category
        ]

    @property
    def count(self) -> int:
        """Total number of registered skills."""
        return len(self._skills)


# Global singleton for class-based skills
skill_registry = SkillRegistry()
