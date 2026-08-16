"""Reusable multi-agent coordination patterns inspired by established AI security systems.

These are planning primitives only. Actual execution remains behind NEXUS policy,
scope, authorization, and tool-executor guards.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AgentRole(str, Enum):
    SUPERVISOR = "supervisor"
    RESEARCHER = "researcher"
    EXECUTOR = "executor"
    VALIDATOR = "validator"
    REFINER = "refiner"
    REPORTER = "reporter"


@dataclass(frozen=True)
class AgentContext:
    mission_id: str
    task_id: str
    role: AgentRole
    objective: str
    evidence_refs: tuple[str, ...] = ()
    prior_task_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Delegation:
    parent_task_id: str
    child_task_id: str
    role: AgentRole
    objective: str
    fresh_context: bool = True


class PlanningPattern:
    """Builds a safe supervisor -> specialist -> validator -> refiner chain."""

    def decompose(self, mission_id: str, task_id: str, objective: str) -> tuple[Delegation, ...]:
        return (
            Delegation(task_id, f"{task_id}:research", AgentRole.RESEARCHER, objective, True),
            Delegation(task_id, f"{task_id}:execute", AgentRole.EXECUTOR, objective, True),
            Delegation(task_id, f"{task_id}:validate", AgentRole.VALIDATOR, objective, True),
            Delegation(task_id, f"{task_id}:refine", AgentRole.REFINER, objective, True),
        )
