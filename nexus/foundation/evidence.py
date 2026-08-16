"""Immutable evidence primitives used to make assessments reproducible."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class Evidence:
    """A content-addressed observation captured during an authorized mission.

    Evidence is immutable by design. Findings may be revised as analysis improves,
    while the original observation remains stable for retesting and audit purposes.
    """

    evidence_id: str
    mission_id: str
    source_tool: str
    asset: str
    captured_at: str
    kind: str = "observation"
    confidence: str = "medium"
    content: dict[str, Any] = field(default_factory=dict)
    sha256: str = ""

    @classmethod
    def create(
        cls,
        mission_id: str,
        source_tool: str,
        asset: str,
        content: dict[str, Any],
        *,
        kind: str = "observation",
        confidence: str = "medium",
    ) -> "Evidence":
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(
            evidence_id=f"ev_{uuid4().hex}",
            mission_id=mission_id,
            source_tool=source_tool,
            asset=asset,
            captured_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            kind=kind,
            confidence=confidence,
            content=content,
            sha256=digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def verify_integrity(self) -> bool:
        canonical = json.dumps(self.content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest() == self.sha256
