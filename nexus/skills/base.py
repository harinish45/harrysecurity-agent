"""
Base skill class for NEXUS-STRIKE.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SkillResult:
    """Result of a skill execution."""
    success: bool
    message: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    tools_used: List[str] = field(default_factory=list)


class Skill:
    """Base class for all security skills."""

    name: str = ""
    category: str = ""
    description: str = ""
    tools: List[str] = []
    prompt_template: str = ""

    def __init__(self, target: str = "127.0.0.1"):
        self.target = target

    def run(self, **kwargs) -> SkillResult:
        """Execute the skill. Override in subclasses."""
        return SkillResult(
            success=True,
            message=f"Skill '{self.name}' executed on {self.target}",
            tools_used=self.tools,
        )

    def get_prompt(self, context: str = "") -> str:
        """Generate the LLM prompt for this skill."""
        return self.prompt_template.format(
            target=self.target,
            context=context,
            tools=", ".join(self.tools),
        )
