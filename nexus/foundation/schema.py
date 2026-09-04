"""
NEXUS-STRIKE — Unified finding schema and status constants.
Every tool, report, and export MUST use this schema and these status values.
"""
from __future__ import annotations

import re
import uuid
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
        if not self.id:
            # The docstring above promises this is "Auto-assigned" — it wasn't,
            # which left every Finding built from a plain dict (the common
            # case: most agents return {"title": ..., "severity": ...} with no
            # id) with id="" all the way through to the rendered report
            # ("### — CRITICAL", blank Finding ID column). A random suffix
            # (not sequential) avoids collisions between Finding objects built
            # independently across concurrent FlowController batches.
            self.id = f"F-{uuid.uuid4().hex[:8].upper()}"
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


# ── Redaction ─────────────────────────────────────────────────────────────
# Finding evidence (and, occasionally, raw tool output) can end up carrying
# live secrets scraped straight off the target — an API key in a response
# body, a bearer token in a captured header, a private key dumped by a
# misconfigured service. Reports and exports should never reproduce those
# verbatim. ``redact_findings()`` strips secret-shaped text out of
# ``evidence``/``raw`` while leaving the rest of the finding untouched.

_AWS_ACCESS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER_TOKEN_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|credential)\s*[:=]\s*([^\s,;]+)"
)

DEFAULT_SECRET_PATTERNS = (
    _PEM_PRIVATE_KEY_RE,
    _AWS_ACCESS_KEY_RE,
    _BEARER_TOKEN_RE,
    _KV_SECRET_RE,
)


def _redact_text(value: str, extra_patterns: list) -> str:
    text = _PEM_PRIVATE_KEY_RE.sub("[REDACTED]", value)
    text = _AWS_ACCESS_KEY_RE.sub("[REDACTED]", text)
    text = _BEARER_TOKEN_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    text = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    for pattern in extra_patterns:
        text = pattern.sub("[REDACTED]", text)
    return text


def _redact_value(value: Any, extra_patterns: list) -> Any:
    if isinstance(value, str):
        return _redact_text(value, extra_patterns)
    if isinstance(value, dict):
        return {k: _redact_value(v, extra_patterns) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(v, extra_patterns) for v in value]
    return value


def redact_findings(findings: list[dict], *, patterns: Optional[list] = None) -> list[dict]:
    """Return a new list of finding dicts with secret-shaped text stripped
    out of the ``evidence`` field (and ``raw``, when it is a ``dict`` or
    ``str``). Every other field — title, severity, remediation, references,
    etc. — is copied through unchanged.

    Built-in redaction rules (always applied):
      - AWS access keys (``AKIA[0-9A-Z]{16}``)
      - PEM private key blocks
      - Bearer tokens (``Bearer <token>``)
      - ``password``/``passwd``/``secret``/``token``/``api_key``/``credential``
        ``key=value`` or ``key: value`` pairs (value only is redacted, the
        key name is preserved as ``key=[REDACTED]``)

    ``patterns`` — optional extra ``re.Pattern`` objects. Each one's full
    match is replaced with ``[REDACTED]`` in addition to (not instead of)
    the built-in rules above, letting callers extend the default list with
    project- or environment-specific secret shapes.
    """
    extra_patterns = list(patterns) if patterns else []
    out: list[dict[str, Any]] = []
    for item in findings:
        new_item = dict(item)
        evidence = new_item.get("evidence")
        if isinstance(evidence, str):
            new_item["evidence"] = _redact_text(evidence, extra_patterns)
        raw = new_item.get("raw")
        if isinstance(raw, (dict, str)):
            new_item["raw"] = _redact_value(raw, extra_patterns)
        out.append(new_item)
    return out