"""Deterministic before/after security assessment differential analysis."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class FindingSnapshot:
    finding_id: str
    severity: str
    status: str = "open"
    evidence_hash: str = ""


@dataclass(frozen=True)
class FindingChange:
    finding_id: str
    change: str
    before: FindingSnapshot | None = None
    after: FindingSnapshot | None = None


class RetestDiffer:
    """Compare normalized finding snapshots without inference from raw prose."""

    def compare(
        self,
        before: Iterable[FindingSnapshot],
        after: Iterable[FindingSnapshot],
    ) -> tuple[FindingChange, ...]:
        old = {item.finding_id: item for item in before}
        new = {item.finding_id: item for item in after}
        changes: list[FindingChange] = []

        for finding_id in sorted(set(old) | set(new)):
            previous = old.get(finding_id)
            current = new.get(finding_id)
            if previous is None:
                changes.append(FindingChange(finding_id, "new", None, current))
            elif current is None:
                changes.append(FindingChange(finding_id, "resolved", previous, None))
            elif previous.evidence_hash != current.evidence_hash or previous.status != current.status or previous.severity != current.severity:
                changes.append(FindingChange(finding_id, "changed", previous, current))
            else:
                changes.append(FindingChange(finding_id, "unchanged", previous, current))
        return tuple(changes)
