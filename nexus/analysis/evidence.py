"""Evidence normalization and deterministic finding correlation.

This module combines observations that describe the same security condition.
It deliberately uses explicit identity fields and normalized values rather than
LLM guesses, so reports can always trace a finding back to its evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import re
from typing import Iterable

_SPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    asset: str
    title: str
    description: str = ""
    severity: str = "info"
    fingerprint: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def normalized_key(self) -> tuple[str, str, str, str]:
        return (
            _normalize(self.asset),
            _normalize(self.title),
            _normalize(self.fingerprint),
            _normalize(self.metadata.get("port", "")),
        )


@dataclass(frozen=True)
class CorrelatedFinding:
    finding_id: str
    asset: str
    title: str
    severity: str
    evidence_ids: tuple[str, ...]
    sources: tuple[str, ...]
    descriptions: tuple[str, ...]


def _normalize(value: str) -> str:
    return _SPACE_RE.sub(" ", value.strip().lower())


def _finding_id(key: tuple[str, str, str, str]) -> str:
    digest = sha256("|".join(key).encode("utf-8")).hexdigest()[:16]
    return f"finding-{digest}"


def correlate(evidence: Iterable[Evidence]) -> tuple[CorrelatedFinding, ...]:
    """Group equivalent observations without losing source provenance."""
    groups: dict[tuple[str, str, str, str], list[Evidence]] = {}
    for item in evidence:
        groups.setdefault(item.normalized_key(), []).append(item)

    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    findings: list[CorrelatedFinding] = []
    for key, items in groups.items():
        ordered = sorted(items, key=lambda item: (item.source, item.evidence_id))
        severity = max(
            (item.severity.lower() for item in ordered),
            key=lambda value: severity_rank.get(value, -1),
        )
        descriptions = tuple(dict.fromkeys(item.description for item in ordered if item.description))
        findings.append(
            CorrelatedFinding(
                finding_id=_finding_id(key),
                asset=ordered[0].asset,
                title=ordered[0].title,
                severity=severity,
                evidence_ids=tuple(item.evidence_id for item in ordered),
                sources=tuple(dict.fromkeys(item.source for item in ordered)),
                descriptions=descriptions,
            )
        )

    return tuple(
        sorted(findings, key=lambda item: (-severity_rank.get(item.severity, -1), item.finding_id))
    )
