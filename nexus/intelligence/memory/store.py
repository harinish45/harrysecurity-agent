"""Durable, bounded mission memory for agent coordination."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Iterable


@dataclass(frozen=True)
class MemoryItem:
    key: str
    value: str
    mission_id: str = ""
    tags: tuple[str, ...] = ()


class MemoryStore:
    """Small deterministic JSON-backed store; replaceable by PostgreSQL/vector backends later."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = RLock()

    def put(self, item: MemoryItem) -> None:
        with self._lock:
            data = self._read()
            data[item.key] = {
                "key": item.key,
                "value": item.value,
                "mission_id": item.mission_id,
                "tags": list(item.tags),
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def get(self, key: str) -> MemoryItem | None:
        item = self._read().get(key)
        if item is None:
            return None
        return MemoryItem(item["key"], item["value"], item.get("mission_id", ""), tuple(item.get("tags", ())))

    def search(self, tags: Iterable[str] = ()) -> tuple[MemoryItem, ...]:
        required = set(tags)
        items = []
        for raw in self._read().values():
            item = MemoryItem(raw["key"], raw["value"], raw.get("mission_id", ""), tuple(raw.get("tags", ())))
            if required.issubset(item.tags):
                items.append(item)
        return tuple(sorted(items, key=lambda item: item.key))

    def _read(self) -> dict[str, dict[str, object]]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        return raw if isinstance(raw, dict) else {}
