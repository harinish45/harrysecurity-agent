"""
NEXUS-STRIKE Skills Plugin System
Launch skills across 7 security domains via chat or API.

Two registries are available:
- skills_registry: Functional registry (dataclass-based, backward-compatible)
- skill_registry: Class-based registry with 7 domain skill modules
"""
# Functional registry — backward-compatible (GitHub PR #2)
from .registry import skills_registry, Skill as SkillDataclass

# Class-based system — enhancement package
from .base import Skill, SkillResult
from .skill_registry import skill_registry

# Auto-register all 7 domain skills into skill_registry
try:
    from . import auto_register  # noqa: F401 — triggers registration side-effects
except ImportError:
    pass  # Graceful fallback if domain skill modules have missing deps

__all__ = [
    "skills_registry",   # functional dataclass-based registry (old style)
    "skill_registry",    # class-based OOP registry (enhancement)
    "Skill",             # base skill class
    "SkillDataclass",    # old dataclass Skill (from registry.py)
    "SkillResult",       # skill execution result dataclass
]