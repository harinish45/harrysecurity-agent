"""Mission service layer — the API/CLI-facing wrapper around ``MissionStore``.

``web/mission_api.py`` (the dashboard's mission-control HTTP adapter) is
written against a ``MissionService`` with ``create``/``list``/``get``/
``transition``/``summarize``/``replay`` methods. This module provides that
class; ``Mission``/``MissionEvent``/``MissionStatus``/``MissionStore`` in
``.models`` remain the underlying dependency-free lifecycle primitives.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import Mission, MissionEvent, MissionStatus, MissionStore


@dataclass(frozen=True)
class MissionEventView:
    """Replay-friendly projection of a ``MissionEvent``.

    ``MissionEvent`` itself has no ``sequence`` field and names its kind
    ``type`` (see models.py / test_mission.py, which already depend on
    that shape) — this view adds a 1-indexed ``sequence`` and exposes the
    kind as ``event_type`` for callers (e.g. the mission-control WS/HTTP
    replay endpoint) that need to page through a mission's event log.
    """

    event_id: str
    mission_id: str
    event_type: str
    timestamp: str
    payload: dict[str, Any]
    sequence: int


class MissionService:
    """High-level operations on top of a ``MissionStore``."""

    def __init__(self, store: MissionStore | str | Path) -> None:
        self.store = store if isinstance(store, MissionStore) else MissionStore(store)

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
            mission_id=f"mission-{uuid4().hex[:12]}",
            target=target,
            mode=mode,
            objective=objective,
            workflow=workflow,
            authorization_reference=authorization_reference,
            metadata=metadata or {},
        )
        mission.record("mission.created", payload={"target": target, "mode": mode})
        self.store.save(mission)
        return mission

    def list(self) -> list[Mission]:
        return self.store.list()

    def get(self, mission_id: str) -> Mission:
        if not self.store.exists(mission_id):
            raise FileNotFoundError(f"Mission {mission_id!r} not found")
        return self.store.load(mission_id)

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

    def summarize(self, mission: Mission) -> Mission:
        """Return the representation callers should serialize via ``to_dict()``.

        Currently the identity function — ``Mission`` already carries a
        complete, dict-serializable view — kept as its own method so a
        slimmer projection (e.g. omitting the full event log) can be
        introduced later without changing callers.
        """
        return mission

    def replay(self, mission_id: str, *, after_sequence: int = 0) -> list[MissionEventView]:
        mission = self.get(mission_id)
        views = [
            MissionEventView(
                event_id=event.event_id,
                mission_id=event.mission_id,
                event_type=event.type,
                timestamp=event.timestamp,
                payload=event.payload,
                sequence=index,
            )
            for index, event in enumerate(mission.events, start=1)
        ]
        return [view for view in views if view.sequence > after_sequence]


__all__ = ["MissionService", "MissionEventView"]
