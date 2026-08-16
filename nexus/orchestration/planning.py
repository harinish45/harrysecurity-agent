"""Validated planner model for capability-driven agent selection."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from nexus.agents.capabilities import AgentCapability, CapabilityRegistry, RiskLevel


class TaskState(str, Enum):
    PLANNED = "planned"
    READY = "ready"
    BLOCKED = "blocked"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class PlanTask:
    task_id: str
    objective: str
    required_capabilities: tuple[str, ...]
    risk_level: RiskLevel = RiskLevel.LOW
    depends_on: tuple[str, ...] = ()
    approval_required: bool = False
    state: TaskState = TaskState.PLANNED
    assigned_agent: str = ""

    def assign(self, agent: AgentCapability) -> "PlanTask":
        if not agent.can_satisfy(self.required_capabilities):
            raise ValueError(f"agent {agent.agent_id} cannot satisfy task capabilities")
        if self.approval_required and not agent.requires_approval:
            # A plan may require more approval than an agent normally does.
            return PlanTask(
                task_id=self.task_id,
                objective=self.objective,
                required_capabilities=self.required_capabilities,
                risk_level=self.risk_level,
                depends_on=self.depends_on,
                approval_required=True,
                state=self.state,
                assigned_agent=agent.agent_id,
            )
        return PlanTask(
            task_id=self.task_id,
            objective=self.objective,
            required_capabilities=self.required_capabilities,
            risk_level=self.risk_level,
            depends_on=self.depends_on,
            approval_required=agent.requires_approval,
            state=self.state,
            assigned_agent=agent.agent_id,
        )


@dataclass(frozen=True)
class ValidatedPlan:
    mission_id: str
    tasks: tuple[PlanTask, ...]
    policy_version: str = "1"

    def ready_tasks(self, completed: Iterable[str] = ()) -> tuple[PlanTask, ...]:
        done = set(completed)
        return tuple(
            task for task in self.tasks
            if task.state in {TaskState.PLANNED, TaskState.READY}
            and set(task.depends_on).issubset(done)
            and task.assigned_agent
        )


class PolicyPlanner:
    """Assigns capabilities under explicit risk policy; LLMs can propose tasks,
    but this layer is responsible for validating and assigning them."""

    def __init__(self, registry: CapabilityRegistry) -> None:
        self.registry = registry

    def assign(self, task: PlanTask, *, max_risk: RiskLevel = RiskLevel.ACTIVE) -> PlanTask:
        eligible = self.registry.eligible(task.required_capabilities, max_risk=max_risk)
        if not eligible:
            raise ValueError(f"no eligible agent for task: {task.task_id}")
        return task.assign(eligible[0])

    def validate(self, mission_id: str, tasks: Iterable[PlanTask], *, policy_version: str = "1") -> ValidatedPlan:
        materialized = tuple(tasks)
        ids = {task.task_id for task in materialized}
        if len(ids) != len(materialized):
            raise ValueError("plan contains duplicate task IDs")
        for task in materialized:
            missing = set(task.depends_on) - ids
            if missing:
                raise ValueError(f"task {task.task_id} has unknown dependencies: {sorted(missing)}")
            if task.risk_level == RiskLevel.DESTRUCTIVE and not task.approval_required:
                raise ValueError("destructive tasks require explicit approval")
        return ValidatedPlan(mission_id=mission_id, tasks=materialized, policy_version=policy_version)
