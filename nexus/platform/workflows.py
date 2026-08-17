"""Unified assessment workflow definitions and deterministic task graphs."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from nexus.platform.capabilities import WorkflowMode


class TaskState(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    BLOCKED = "blocked"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class WorkflowTask:
    id: str
    title: str
    capability: str
    depends_on: tuple[str, ...] = ()
    priority: int = 100
    requires_approval: bool = False
    state: TaskState = TaskState.PENDING


@dataclass
class TaskGraph:
    tasks: dict[str, WorkflowTask] = field(default_factory=dict)

    def add(self, task: WorkflowTask) -> None:
        if task.id in self.tasks:
            raise ValueError(f"duplicate task: {task.id}")
        missing = [item for item in task.depends_on if item not in self.tasks]
        if missing:
            raise ValueError(f"missing dependencies for {task.id}: {missing}")
        if task.id in task.depends_on:
            raise ValueError("task cannot depend on itself")
        self.tasks[task.id] = task

    def ready(self) -> list[WorkflowTask]:
        completed = {task.id for task in self.tasks.values() if task.state == TaskState.SUCCEEDED}
        failed = {
            task.id
            for task in self.tasks.values()
            if task.state in {TaskState.FAILED, TaskState.CANCELLED, TaskState.BLOCKED}
        }
        result = [
            task
            for task in self.tasks.values()
            if task.state in {TaskState.PENDING, TaskState.READY}
            and not any(item in failed for item in task.depends_on)
            and all(item in completed for item in task.depends_on)
        ]
        return sorted(result, key=lambda task: (-task.priority, task.id))

    def blocked(self) -> list[WorkflowTask]:
        failed = {
            task.id
            for task in self.tasks.values()
            if task.state in {TaskState.FAILED, TaskState.CANCELLED, TaskState.BLOCKED}
        }
        return sorted(
            [
                task
                for task in self.tasks.values()
                if task.state in {TaskState.PENDING, TaskState.READY}
                and any(item in failed for item in task.depends_on)
            ],
            key=lambda task: task.id,
        )

    def execution_order(self) -> list[str]:
        """Return a deterministic dependency-first topological execution order."""
        remaining = set(self.tasks)
        ordered: list[str] = []
        while remaining:
            candidates = [
                task
                for task_id, task in self.tasks.items()
                if task_id in remaining
                and all(item not in remaining for item in task.depends_on)
            ]
            if not candidates:
                raise ValueError("task graph contains a dependency cycle")
            chosen = max(candidates, key=lambda task: (task.priority, task.id))
            ordered.append(chosen.id)
            remaining.remove(chosen.id)
        return ordered

    def critical_path(self) -> list[str]:
        """Backward-compatible alias for deterministic execution ordering.

        True duration-weighted critical-path analysis belongs to the performance
        planner and requires measured task durations; this method intentionally
        does not pretend priority is elapsed time.
        """
        return self.execution_order()


@dataclass(frozen=True)
class WorkflowSpec:
    mode: WorkflowMode
    title: str
    objective: str
    tasks: tuple[WorkflowTask, ...]


class WorkflowCatalog:
    def __init__(self) -> None:
        self._workflows: dict[WorkflowMode, WorkflowSpec] = {}

    def register(self, workflow: WorkflowSpec) -> None:
        self._workflows[workflow.mode] = workflow

    def get(self, mode: WorkflowMode) -> WorkflowSpec:
        return self._workflows[mode]

    def list(self) -> list[WorkflowSpec]:
        return [self._workflows[mode] for mode in sorted(self._workflows, key=lambda item: item.value)]


workflows = WorkflowCatalog()


def _standard_assessment_tasks() -> tuple[WorkflowTask, ...]:
    return (
        WorkflowTask("recon", "Asset discovery", "agent.recon", priority=100),
        WorkflowTask("surface", "Attack-surface mapping", "intelligence.target_fingerprinting", depends_on=("recon",), priority=95),
        WorkflowTask("assessment", "Vulnerability assessment", "agent.validation", depends_on=("surface",), priority=90, requires_approval=True),
        WorkflowTask("correlate", "Evidence correlation", "intelligence.evidence_correlation", depends_on=("assessment",), priority=80),
        WorkflowTask("report", "Professional reporting", "reporting.machine_readable", depends_on=("correlate",), priority=40),
    )


for mode, title, objective in [
    (WorkflowMode.PENTEST, "Penetration Test", "Authorized security assessment"),
    (WorkflowMode.GUIDED, "Guided Assessment", "Human-guided security assessment"),
    (WorkflowMode.AUTONOMOUS, "Autonomous Assessment", "Bounded autonomous security assessment"),
    (WorkflowMode.SCHEDULED, "Scheduled Assessment", "Repeatable security validation"),
]:
    workflows.register(WorkflowSpec(mode, title, objective, _standard_assessment_tasks()))

workflows.register(WorkflowSpec(
    WorkflowMode.PURPLE_TEAM,
    "Purple Team Validation",
    "Validate attack controls against defensive detections",
    (
        WorkflowTask("attack_sim", "Authorized attack simulation", "agent.exploit", priority=100, requires_approval=True),
        WorkflowTask("observe", "Collect defensive observations", "agent.detection_engineering", depends_on=("attack_sim",), priority=90),
        WorkflowTask("gap", "Analyze detection gap", "agent.purple_team", depends_on=("observe",), priority=80),
        WorkflowTask("improve", "Generate detection improvement", "defense.detection_engineering", depends_on=("gap",), priority=70),
        WorkflowTask("retest", "Retest control", "workflow.vulnerability_research", depends_on=("improve",), priority=60, requires_approval=True),
    ),
))

workflows.register(WorkflowSpec(
    WorkflowMode.VULNERABILITY_RESEARCH,
    "Vulnerability Research",
    "Progress candidate observations toward validated evidence and remediation",
    (
        WorkflowTask("scan", "Candidate scanner", "agent.recon", priority=100),
        WorkflowTask("detect", "Candidate detector", "agent.validation", depends_on=("scan",), priority=90),
        WorkflowTask("verify", "Independent validation", "agent.validation", depends_on=("detect",), priority=85),
        WorkflowTask("evidence", "Evidence normalization", "evidence.immutable_provenance", depends_on=("verify",), priority=75),
        WorkflowTask("patch", "Remediation guidance", "reporting.developer", depends_on=("evidence",), priority=50),
    ),
))

workflows.register(WorkflowSpec(
    WorkflowMode.CTF,
    "CTF Assessment",
    "Challenge-solving with explicit checkpoints",
    (
        WorkflowTask("recon", "Challenge reconnaissance", "agent.recon", priority=100),
        WorkflowTask("hypothesis", "Hypothesis generation", "agent.researcher", depends_on=("recon",), priority=95),
        WorkflowTask("validate", "Controlled validation", "agent.validation", depends_on=("hypothesis",), priority=85, requires_approval=True),
        WorkflowTask("walkthrough", "Reproducible walkthrough", "reporting.technical", depends_on=("validate",), priority=40),
    ),
))

workflows.register(WorkflowSpec(
    WorkflowMode.RESEARCH,
    "Security Research",
    "Run reproducible agent, model, or tool experiments",
    (
        WorkflowTask("setup", "Experiment setup", "research.experiment_builder", priority=100),
        WorkflowTask("run", "Experiment execution", "agent.executor", depends_on=("setup",), priority=90),
        WorkflowTask("measure", "Measure quality and cost", "research.success_rate", depends_on=("run",), priority=80),
        WorkflowTask("report", "Reproducible experiment report", "reporting.machine_readable", depends_on=("measure",), priority=40),
    ),
))
