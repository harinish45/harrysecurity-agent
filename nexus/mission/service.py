"""Application service layer for mission lifecycle operations."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Mission, MissionEvent, MissionStatus, MissionStore


@dataclass(frozen=True)
class MissionSummary:
    """Stable dashboard-facing projection of a mission."""

    mission_id: str
    target: str
    status: str
    mode: str
    objective: str
    workflow: str
    authorization_reference: str
    created_at: str
    updated_at: str
    event_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "status": self.status,
            "mode": self.mode,
            "objective": self.objective,
            "workflow": self.workflow,
            "authorization_reference": self.authorization_reference,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "event_count": self.event_count,
        }


class MissionService:
    """Coordinates mission models and persistence for local dashboard/API callers."""

    def __init__(self, store: MissionStore) -> None:
        self.store = store

    def create(
        self,
        target: str,
        *,
        mode: str = "guided",
        objective: str = "full_assessment",
        workflow: str = "full_assessment",
        authorization_reference: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Mission:
        target = str(target).strip()
        if not target:
            raise ValueError("target must be a non-empty string")
        mission = Mission(
            mission_id=f"mis_{__import__('uuid').uuid4().hex}",
            target=target,
            mode=mode,
            objective=objective,
            workflow=workflow,
            authorization_reference=authorization_reference,
            metadata=metadata or {},
        )
        mission.record("mission.created", actor="dashboard", payload={"target": target})
        self.store.save(mission)
        return mission

    def get(self, mission_id: str) -> Mission:
        return self.store.load(mission_id)

    def list(self) -> list[Mission]:
        return sorted(self.store.list(), key=lambda mission: mission.updated_at, reverse=True)

    def summarize(self, mission: Mission) -> MissionSummary:
        return MissionSummary(
            mission_id=mission.mission_id,
            target=mission.target,
            status=mission.status.value,
            mode=mission.mode,
            objective=mission.objective,
            workflow=mission.workflow,
            authorization_reference=mission.authorization_reference,
            created_at=mission.created_at,
            updated_at=mission.updated_at,
            event_count=len(mission.events),
        )

    def transition(
        self,
        mission_id: str,
        status: MissionStatus,
        *,
        actor: str = "system",
        reason: str = "",
    ) -> Mission:
        mission = self.get(mission_id)
        mission.transition(status, actor=actor, reason=reason)
        self.store.save(mission)
        return mission

    def replay(self, mission_id: str, *, after_sequence: int = 0) -> list[MissionEvent]:
        mission = self.get(mission_id)
        if after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        return mission.events[after_sequence:]
