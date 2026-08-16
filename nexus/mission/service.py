"""Mission control service shared by CLI, dashboard, and future workers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus.runtime.events import Event, EventBus

from .models import Mission, MissionEvent, MissionStatus, MissionStore


@dataclass(frozen=True)
class MissionSummary:
    """Safe mission projection for APIs and dashboards."""

    mission_id: str
    target: str
    status: str
    mode: str
    objective: str
    workflow: str
    created_at: str
    updated_at: str
    authorization_reference: str

    def to_dict(self) -> dict[str, str]:
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "status": self.status,
            "mode": self.mode,
            "objective": self.objective,
            "workflow": self.workflow,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "authorization_reference": self.authorization_reference,
        }


class MissionService:
    """Coordinate durable mission state and replayable telemetry."""

    def __init__(self, store: MissionStore | None = None, event_bus: EventBus | None = None) -> None:
        self.store = store or MissionStore()
        self.events = event_bus or EventBus()

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
        mission = Mission(
            mission_id=self._new_id(),
            target=target,
            mode=mode,
            objective=objective,
            workflow=workflow,
            authorization_reference=authorization_reference,
            metadata=metadata or {},
        )
        self._save_and_publish(mission, mission.record("mission.created", payload={"target": target, "mode": mode}))
        return mission

    def transition(self, mission_id: str, status: MissionStatus, *, actor: str = "system", reason: str = "") -> Mission:
        mission = self.store.load(mission_id)
        event = mission.transition(status, actor=actor, reason=reason)
        self._save_and_publish(mission, event)
        return mission

    def record(self, mission_id: str, event_type: str, *, actor: str = "system", payload: dict[str, Any] | None = None) -> Mission:
        mission = self.store.load(mission_id)
        event = mission.record(event_type, actor=actor, payload=payload)
        self._save_and_publish(mission, event)
        return mission

    def get(self, mission_id: str) -> Mission:
        return self.store.load(mission_id)

    def list(self) -> list[MissionSummary]:
        return [self.summarize(mission) for mission in self.store.list()]

    @staticmethod
    def summarize(mission: Mission) -> MissionSummary:
        return MissionSummary(
            mission_id=mission.mission_id,
            target=mission.target,
            status=mission.status.value,
            mode=mission.mode,
            objective=mission.objective,
            workflow=mission.workflow,
            created_at=mission.created_at,
            updated_at=mission.updated_at,
            authorization_reference=mission.authorization_reference,
        )

    def replay(self, mission_id: str, *, after_sequence: int = 0) -> tuple[Event, ...]:
        return self.events.replay(mission_id=mission_id, after_sequence=after_sequence)

    def _save_and_publish(self, mission: Mission, mission_event: MissionEvent) -> None:
        self.store.save(mission)
        self.events.publish(
            Event(
                event_id=mission_event.event_id,
                mission_id=mission_event.mission_id,
                event_type=mission_event.type,
                timestamp=mission_event.timestamp,
                payload=dict(mission_event.payload),
            )
        )

    @staticmethod
    def _new_id() -> str:
        from uuid import uuid4

        return f"mission_{uuid4().hex}"


def default_mission_service(root: str | Path = "engagements/missions") -> MissionService:
    """Factory kept separate so deployments can inject another store later."""

    return MissionService(MissionStore(root))
