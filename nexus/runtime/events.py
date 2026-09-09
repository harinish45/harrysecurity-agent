"""Replayable event fabric for mission telemetry and worker coordination."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Callable, Iterable


@dataclass(frozen=True)
class Event:
    event_id: str
    mission_id: str
    event_type: str
    timestamp: str
    payload: dict[str, object]
    sequence: int = 0


Subscriber = Callable[[Event], None]


class EventBus:
    """In-memory event log with deterministic replay and subscriber isolation."""

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._subscribers: list[Subscriber] = []
        self._lock = RLock()

    @property
    def events(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._events)

    def publish(self, event: Event) -> Event:
        with self._lock:
            if any(existing.event_id == event.event_id for existing in self._events):
                raise ValueError(f"duplicate event id: {event.event_id}")
            committed = Event(
                event.event_id,
                event.mission_id,
                event.event_type,
                event.timestamp,
                dict(event.payload),
                len(self._events) + 1,
            )
            self._events.append(committed)
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber(committed)
            except Exception:
                # One observer must never break mission telemetry delivery.
                continue
        return committed

    def subscribe(self, subscriber: Subscriber) -> None:
        with self._lock:
            if subscriber not in self._subscribers:
                self._subscribers.append(subscriber)

    def replay(self, *, mission_id: str | None = None, after_sequence: int = 0) -> tuple[Event, ...]:
        with self._lock:
            return tuple(
                event for event in self._events
                if event.sequence > after_sequence
                and (mission_id is None or event.mission_id == mission_id)
            )
