"""Mission lifecycle, events, and a small durable JSON mission store.

The store is intentionally dependency-free so the local CLI and dashboard can use
identical mission semantics. A database-backed repository can implement the same
protocol later without changing callers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any
from uuid import uuid4


class MissionStatus(str, Enum):
    CREATED = "created"
    AUTHORIZED = "authorized"
    PLANNING = "planning"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_APPROVAL = "waiting_approval"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


_TERMINAL = frozenset({
    MissionStatus.COMPLETED,
    MissionStatus.FAILED,
    MissionStatus.BLOCKED,
    MissionStatus.CANCELLED,
})

_ALLOWED: dict[MissionStatus, frozenset[MissionStatus]] = {
    MissionStatus.CREATED: frozenset({MissionStatus.AUTHORIZED, MissionStatus.BLOCKED}),
    MissionStatus.AUTHORIZED: frozenset({MissionStatus.PLANNING, MissionStatus.BLOCKED}),
    MissionStatus.PLANNING: frozenset({MissionStatus.QUEUED, MissionStatus.FAILED, MissionStatus.BLOCKED}),
    MissionStatus.QUEUED: frozenset({MissionStatus.RUNNING, MissionStatus.CANCELLING, MissionStatus.BLOCKED}),
    MissionStatus.RUNNING: frozenset({MissionStatus.PAUSED, MissionStatus.WAITING_APPROVAL, MissionStatus.CANCELLING, MissionStatus.COMPLETED, MissionStatus.FAILED}),
    MissionStatus.PAUSED: frozenset({MissionStatus.RUNNING, MissionStatus.CANCELLING}),
    MissionStatus.WAITING_APPROVAL: frozenset({MissionStatus.RUNNING, MissionStatus.CANCELLING, MissionStatus.BLOCKED}),
    MissionStatus.CANCELLING: frozenset({MissionStatus.CANCELLED, MissionStatus.FAILED}),
}


@dataclass(frozen=True)
class MissionEvent:
    """Immutable event suitable for WebSocket replay and audit storage."""

    event_id: str
    mission_id: str
    type: str
    timestamp: str
    actor: str = "system"
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def event_type(self) -> str:
        """Dashboard/API-compatible alias for the canonical event type."""
        return self.type

    def sequence(self, events: list["MissionEvent"] | None = None) -> int:
        """Return a one-based event sequence when an event collection is supplied."""
        if events is None:
            return 0
        return events.index(self) + 1

    @classmethod
    def create(cls, mission_id: str, event_type: str, *, actor: str = "system", payload: dict[str, Any] | None = None) -> "MissionEvent":
        return cls(
            event_id=f"evt_{uuid4().hex}",
            mission_id=mission_id,
            type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            actor=actor,
            payload=payload or {},
        )


@dataclass
class Mission:
    mission_id: str
    target: str
    status: MissionStatus = MissionStatus.CREATED
    mode: str = "guided"
    objective: str = "full_assessment"
    workflow: str = "full_assessment"
    authorization_reference: str = ""
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    events: list[MissionEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.created_at = self.created_at or now
        self.updated_at = self.updated_at or self.created_at
        if not isinstance(self.status, MissionStatus):
            self.status = MissionStatus(self.status)

    def transition(self, new_status: MissionStatus, *, actor: str = "system", reason: str = "") -> MissionEvent:
        new_status = MissionStatus(new_status)
        if self.status == new_status:
            return self.record("mission.status_unchanged", actor=actor, payload={"status": new_status.value})
        if self.status in _TERMINAL:
            raise ValueError(f"Mission {self.mission_id} is terminal ({self.status.value})")
        if new_status not in _ALLOWED.get(self.status, frozenset()):
            raise ValueError(f"Invalid mission transition: {self.status.value} -> {new_status.value}")
        previous = self.status
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return self.record("mission.status_changed", actor=actor, payload={"from": previous.value, "to": new_status.value, "reason": reason})

    def record(self, event_type: str, *, actor: str = "system", payload: dict[str, Any] | None = None) -> MissionEvent:
        event = MissionEvent.create(self.mission_id, event_type, actor=actor, payload=payload)
        self.events.append(event)
        self.updated_at = event.timestamp
        return event

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["events"] = [asdict(event) for event in self.events]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Mission":
        raw = dict(data)
        events = [MissionEvent(**event) for event in raw.pop("events", [])]
        return cls(events=events, status=MissionStatus(raw.pop("status", MissionStatus.CREATED.value)), **raw)


class MissionStore:
    """Atomic JSON-backed mission store for single-host deployments."""

    def __init__(self, root: str | Path = "engagements/missions") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, mission_id: str) -> Path:
        safe = "".join(c for c in mission_id if c.isalnum() or c in "-_.")
        if not safe:
            raise ValueError("mission_id must contain at least one safe character")
        return self.root / f"{safe}.json"

    def save(self, mission: Mission) -> Path:
        path = self.path_for(mission.mission_id)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(mission.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(path)
        return path

    def load(self, mission_id: str) -> Mission:
        return Mission.from_dict(json.loads(self.path_for(mission_id).read_text(encoding="utf-8")))

    def exists(self, mission_id: str) -> bool:
        return self.path_for(mission_id).exists()

    def list(self) -> list[Mission]:
        missions: list[Mission] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                missions.append(Mission.from_dict(json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                continue
        return missions
