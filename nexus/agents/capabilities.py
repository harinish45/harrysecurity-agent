"""Typed contracts describing what an agent is allowed and able to do.

Capabilities are planner-facing metadata. They do not grant authority by
 themselves; scope, legal, escalation, and execution guards remain mandatory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class RiskLevel(str, Enum):
    PASSIVE = "passive"
    LOW = "low"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class AgentCapability:
    agent_id: str
    name: str
    version: str = "1.0"
    domains: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    required_tools: tuple[str, ...] = ()
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    supports_parallelism: bool = True
    supports_resume: bool = True

    def can_satisfy(self, required: Iterable[str]) -> bool:
        available = set(self.capabilities)
        return set(required).issubset(available)

    def to_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "domains": list(self.domains),
            "capabilities": list(self.capabilities),
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level.value,
            "requires_approval": self.requires_approval,
            "supports_parallelism": self.supports_parallelism,
            "supports_resume": self.supports_resume,
        }


class CapabilityRegistry:
    """Deterministic registry used by planning and UI introspection."""

    def __init__(self, agents: Iterable[AgentCapability] = ()) -> None:
        self._agents = {agent.agent_id: agent for agent in agents}

    def register(self, agent: AgentCapability) -> None:
        existing = self._agents.get(agent.agent_id)
        if existing and existing != agent:
            raise ValueError(f"agent capability already registered: {agent.agent_id}")
        self._agents[agent.agent_id] = agent

    def get(self, agent_id: str) -> AgentCapability:
        return self._agents[agent_id]

    def eligible(self, required: Iterable[str], *, max_risk: RiskLevel = RiskLevel.ACTIVE) -> tuple[AgentCapability, ...]:
        order = {
            RiskLevel.PASSIVE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.ACTIVE: 2,
            RiskLevel.DESTRUCTIVE: 3,
        }
        required_set = set(required)
        return tuple(
            sorted(
                (
                    agent for agent in self._agents.values()
                    if required_set.issubset(agent.capabilities)
                    and order[agent.risk_level] <= order[max_risk]
                ),
                key=lambda agent: (order[agent.risk_level], agent.agent_id),
            )
        )

    def to_dict(self) -> list[dict[str, object]]:
        return [agent.to_dict() for agent in sorted(self._agents.values(), key=lambda item: item.agent_id)]
