"""Mission-progress persistence, so a mission interrupted mid-run (crash,
restart) has a durable record of which batches completed and what context
had been handed forward — enough to inspect or resume from, rather than
losing all progress silently."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from nexus.foundation.paths import safe_join, safe_slug


def _checkpoint_dir() -> Path:
    override = os.environ.get("NEXUS_CHECKPOINT_DIR")
    path = Path(override) if override else Path.home() / ".nexus" / "checkpoints"
    path.mkdir(parents=True, exist_ok=True)
    return path


class Checkpoint:
    def __init__(self, checkpoint_dir: Path | None = None) -> None:
        self._dir = checkpoint_dir or _checkpoint_dir()

    def _path(self, mission_id: str) -> Path:
        return safe_join(self._dir, f"{safe_slug(mission_id)}.json")

    def save(self, mission_id: str, state: dict[str, Any]) -> Path:
        path = self._path(mission_id)
        path.write_text(json.dumps(state, default=str, indent=2), encoding="utf-8")
        return path

    def load(self, mission_id: str) -> dict[str, Any] | None:
        path = self._path(mission_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def exists(self, mission_id: str) -> bool:
        return self._path(mission_id).exists()

    def clear(self, mission_id: str) -> None:
        self._path(mission_id).unlink(missing_ok=True)
