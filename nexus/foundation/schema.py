"""
NEXUS-STRIKE — Unified finding schema and status constants.
Every tool, report, and export MUST use this schema and these status values.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


# ── Statuses ──────────────────────────────────────────────────────────────────
# Every tool's result dict MUST include one of these as the "status" key value.

STATUS_COMPLETED = "completed"               # Tool ran OK with or without findings
STATUS_NO_FINDINGS = "no_findings"           # Tool ran OK, zero findings
STATUS_FAILED = "failed"                     # Tool encountered an error
STATUS_UNAVAILABLE = "unavailable"           # Tool cannot run in this environment
STATUS_OUT_OF_SCOPE = "out_of_scope"         # Target not covered by this tool
STATUS_REQUIRES_CREDENTIALS = "requires_credentials"   # Need API keys / creds
STATUS_REQUIRES_HARDWARE = "requires_hardware"         # Need hardware device
STATUS_NOT_IMPLEMENTED = "not_implemented"   # Not yet written

ALL_STATUSES = frozenset({
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
    STATUS_UNAVAILABLE,
    STATUS_OUT_OF_SCOPE,
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_REQUIRES_HARDWARE,
    STATUS_NOT_IMPLEMENTED,
})


# ── Finding Schema (single source of truth) ──────────────────────────────────

@dataclass
class Finding:
    """Every finding MUST be an instance of this dataclass.

    Fields
    ------
    id : str             Auto‑assigned: ``F-001``
    title : str          Short human‑readable title
    severity : str       One of ``critical``, ``high``, ``medium``, ``low``, ``info``
    confidence : str     One of ``certain``, ``high``, ``medium``, ``low``, ``tentative``
    affected_asset : str The host, URL, resource, or component where the issue exists
    evidence : str       Machine‑parseable evidence (snippet, log line, response)
    remediation : str    Action the asset owner should take
    references : list    URLs or identifiers (CVE, CWE, etc.)
    timestamp : str      ISO‑8601 UTC when the finding was created
    tool : str           Fully‑qualified tool name, e.g. ``network.port_scan``
    tool_version : str   Tool / package version from metadata
    raw : dict           Original tool output (optional, not for display)
    """

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
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sev = self.severity.lower()
        if sev not in self.SEVERITY_ORDER:
            self.severity = "info"
        conf = self.confidence.lower()
        if conf not in self.CONFIDENCE_ORDER:
            self.confidence = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Result builder (used by every tool) ──────────────────────────────────────

def tool_result(
    tool_name: str,
    target: str,
    status: str = STATUS_COMPLETED,
    findings: Optional[list[Finding | dict]] = None,
    summary: Optional[str] = None,
    error: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict[str, Any]:
    """Build a standardised tool result dictionary.

    Example
    -------
    >>> tool_result("network.port_scan", "10.0.0.1",
    ...             findings=[Finding(title="Open port 22", severity="medium")],
    ...             summary="Found 3 open ports")
    """
    if status not in ALL_STATUSES:
        status = STATUS_FAILED

    normalised: list[dict[str, Any]] = []
    for f in (findings or []):
        if isinstance(f, Finding):
            normalised.append(f.to_dict())
        elif isinstance(f, dict):
            normalised.append(Finding(**f).to_dict())
        else:
            normalised.append(Finding(description=str(f)).to_dict())

    result: dict[str, Any] = {
        "tool": tool_name,
        "target": target,
        "status": status,
        "findings": normalised,
        "summary": summary or "",
        "error": error or "",
        "metadata": metadata or {},
    }
    return result


def normalize_findings(
    raw_findings: list[Any],
    *,
    tool: str = "",
    tool_version: str = "",
    affected_asset: str = "",
) -> list[dict[str, Any]]:
    """Convert arbitrary finding formats into the canonical dict format."""
    out: list[dict[str, Any]] = []
    for i, item in enumerate(raw_findings, 1):
        if isinstance(item, Finding):
            out.append(item.to_dict())
        elif isinstance(item, dict):
            out.append(Finding(**item).to_dict())
        else:
            desc = str(item)
            sev = "info"
            for s in Finding.SEVERITY_ORDER:
                if s in desc.lower():
                    sev = s
                    break
            out.append(Finding(
                id=f"F-{i:03d}",
                title=desc[:80],
                severity=sev,
                tool=tool,
                tool_version=tool_version,
                affected_asset=affected_asset,
            ).to_dict())
    return out