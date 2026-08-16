"""NEXUS-STRIKE canonical result and finding contracts."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

STATUS_COMPLETED = "completed"
STATUS_NO_FINDINGS = "no_findings"
STATUS_FAILED = "failed"
STATUS_UNAVAILABLE = "unavailable"
STATUS_OUT_OF_SCOPE = "out_of_scope"
STATUS_REQUIRES_CREDENTIALS = "requires_credentials"
STATUS_REQUIRES_HARDWARE = "requires_hardware"
STATUS_NOT_IMPLEMENTED = "not_implemented"
STATUS_SCHEMA_ERROR = "schema_error"

ALL_STATUSES = frozenset({
    STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE,
    STATUS_OUT_OF_SCOPE, STATUS_REQUIRES_CREDENTIALS, STATUS_REQUIRES_HARDWARE,
    STATUS_NOT_IMPLEMENTED, STATUS_SCHEMA_ERROR,
})


@dataclass
class Finding:
    """Canonical finding contract shared by tools, correlation and reports."""

    id: str = ""
    title: str = ""
    severity: str = "info"
    confidence: str = "medium"
    affected_asset: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: str = ""
    tool: str = ""
    tool_version: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
    CONFIDENCE_ORDER = ("certain", "high", "medium", "low", "tentative")

    def __post_init__(self) -> None:
        self.severity = str(self.severity).lower()
        self.confidence = str(self.confidence).lower()
        if self.severity not in self.SEVERITY_ORDER:
            raise ValueError(f"Invalid finding severity: {self.severity}")
        if self.confidence not in self.CONFIDENCE_ORDER:
            raise ValueError(f"Invalid finding confidence: {self.confidence}")
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not self.title.strip():
            raise ValueError("Finding title must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _coerce_finding(item: Any, *, tool: str, tool_version: str, affected_asset: str, index: int) -> Finding:
    if isinstance(item, Finding):
        return item
    if isinstance(item, dict):
        allowed = {field for field in Finding.__dataclass_fields__ if field not in {"SEVERITY_ORDER", "CONFIDENCE_ORDER"}}
        unknown = set(item) - allowed
        if unknown:
            raise ValueError(f"Unknown finding fields: {sorted(unknown)}")
        values = dict(item)
        values.setdefault("tool", tool)
        values.setdefault("tool_version", tool_version)
        values.setdefault("affected_asset", affected_asset)
        return Finding(**values)
    text = str(item).strip()
    if not text:
        raise ValueError(f"Finding {index} is empty")
    return Finding(
        id=f"F-{index:03d}", title=text[:160], evidence=text,
        tool=tool, tool_version=tool_version, affected_asset=affected_asset,
    )


def normalize_findings(raw_findings: list[Any], *, tool: str = "", tool_version: str = "", affected_asset: str = "") -> list[dict[str, Any]]:
    """Normalize findings without silently weakening malformed tool output."""
    return [
        _coerce_finding(item, tool=tool, tool_version=tool_version, affected_asset=affected_asset, index=i).to_dict()
        for i, item in enumerate(raw_findings, 1)
    ]


def tool_result(tool_name: str, target: str, status: str = STATUS_COMPLETED,
                findings: Optional[list[Finding | dict | str]] = None,
                summary: Optional[str] = None, error: Optional[str] = None,
                metadata: Optional[dict] = None) -> dict[str, Any]:
    """Build a standardized tool result; malformed findings fail closed."""
    if status not in ALL_STATUSES:
        status = STATUS_SCHEMA_ERROR
    try:
        normalized = normalize_findings(findings or [], tool=tool_name, affected_asset=target)
    except (TypeError, ValueError) as exc:
        return {
            "tool": tool_name, "target": target, "status": STATUS_SCHEMA_ERROR,
            "findings": [], "summary": summary or "", "error": str(exc),
            "metadata": metadata or {},
        }
    return {
        "tool": tool_name, "target": target, "status": status,
        "findings": normalized, "summary": summary or "", "error": error or "",
        "metadata": metadata or {},
    }
