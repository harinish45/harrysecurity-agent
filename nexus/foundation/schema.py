"""NEXUS-STRIKE canonical result and finding contracts."""
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
STATUS_REQUIRES_FILE = "requires_file"       # Need a local file path (not a network host)
STATUS_REQUIRES_SANDBOX = "requires_sandbox"  # Needs dynamic/sandboxed execution, not performed here
STATUS_NOT_IMPLEMENTED = "not_implemented"   # Not yet written
STATUS_SCHEMA_ERROR = "schema_error"         # Malformed findings/result shape — fails closed, not a crash

ALL_STATUSES = frozenset({
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
    STATUS_UNAVAILABLE,
    STATUS_OUT_OF_SCOPE,
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_REQUIRES_HARDWARE,
    STATUS_REQUIRES_FILE,
    STATUS_REQUIRES_SANDBOX,
    STATUS_NOT_IMPLEMENTED,
    STATUS_SCHEMA_ERROR,
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

    # Populated by the post-processing agents in the orchestration pipeline
    # (verification_agent, blast_radius_agent, mitre_mapping_agent,
    # attack_chain_agent) — additive/optional, every existing exporter keeps
    # working whether or not it chooses to display these.
    verification_status: str = ""
    verification_detail: str = ""
    business_impact: str = ""
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    kind: str = ""
    chain_assets: list[str] = field(default_factory=list)

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
        # An upstream agent/tool emitting severity/confidence as None (a
        # check that failed to classify) or a non-string (e.g. an int) used
        # to crash here with AttributeError on .lower() — since every
        # exporter/report/agent funnels findings through this constructor,
        # that took down the whole reporting pipeline for one bad finding.
        # Treat anything that isn't a recognized string value as "info"/
        # "medium" instead of trusting it's already a lowercase string.
        #
        # NOTE for future merges: an earlier merge of origin/master's schema.py
        # auto-inserted a *raising* severity/confidence check immediately
        # above this comment, with no textual overlap against this method's
        # HEAD-side content — git didn't flag it as a conflict, but it made
        # the coercion below unreachable dead code and reintroduced the exact
        # crash this comment describes fixing. Do not re-add an unconditional
        # `raise ValueError` on invalid severity/confidence here; malformed
        # input must be coerced, not raised, since Finding() is constructed
        # directly (not only via normalize_findings()/_coerce_finding(),
        # which already validate stricter external input at the boundary)
        # across hundreds of call sites that assume this never raises.
        sev = str(self.severity).lower() if self.severity is not None else ""
        if sev not in self.SEVERITY_ORDER:
            self.severity = "info"
        else:
            self.severity = sev
        conf = str(self.confidence).lower() if self.confidence is not None else ""
        if conf not in self.CONFIDENCE_ORDER:
            self.confidence = "medium"
        else:
            self.confidence = conf
        # A finding with no title at all is never legitimate (nothing in
        # this codebase intentionally constructs one — verified) and would
        # render as a blank line in every report; unlike severity/
        # confidence, there's no reasonable default to coerce to here, so
        # this one genuinely should raise.
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


def _coerce_finding(item: Any, *, tool: str, tool_version: str, affected_asset: str, index: int) -> Finding:
    """Coerce one raw finding item (a `Finding`, a plain dict, or a bare
    string) into a real `Finding`, raising ValueError/TypeError on anything
    genuinely malformed (an unrecognized dict key, an empty string item)
    instead of silently guessing — `tool_result()` catches that and fails
    closed to STATUS_SCHEMA_ERROR rather than propagating a crash. This
    check is deliberately at the ingestion boundary only: `Finding.__init__`
    itself stays forgiving (coerces a bad severity/confidence rather than
    raising), since it's constructed directly across hundreds of call sites
    that assume it never raises — see the comment in `__post_init__`."""
    if isinstance(item, Finding):
        return item
    if isinstance(item, dict):
        allowed = {f for f in Finding.__dataclass_fields__ if f not in {"SEVERITY_ORDER", "CONFIDENCE_ORDER"}}
        unknown = set(item) - allowed
        if unknown:
            raise ValueError(f"Unknown finding fields: {sorted(unknown)}")
        values = dict(item)
        values.setdefault("tool", tool)
        values.setdefault("tool_version", tool_version)
        values.setdefault("affected_asset", affected_asset)
        return Finding(**values)
    # A plain string finding (several agents/tools still emit these, e.g.
    # mission_commander_agent's recon summaries) — infer severity by keyword
    # rather than defaulting to "info" for everything.
    text = str(item).strip()
    if not text:
        raise ValueError(f"Finding {index} is empty")
    sev = "info"
    for s in Finding.SEVERITY_ORDER:
        if s in text.lower():
            sev = s
            break
    return Finding(
        id=f"F-{index:03d}", title=text[:160], evidence=text, severity=sev,
        tool=tool, tool_version=tool_version, affected_asset=affected_asset,
    )


def normalize_findings(
    raw_findings: list[Any],
    *,
    tool: str = "",
    tool_version: str = "",
    affected_asset: str = "",
) -> list[dict[str, Any]]:
    """Convert arbitrary finding formats into the canonical dict format.
    Raises ValueError/TypeError on a genuinely malformed item — callers that
    need "never raise" behavior should go through `tool_result()`, which
    catches this and fails closed to STATUS_SCHEMA_ERROR."""
    return [
        _coerce_finding(item, tool=tool, tool_version=tool_version, affected_asset=affected_asset, index=i).to_dict()
        for i, item in enumerate(raw_findings, 1)
    ]


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
        # `title` also needs this: a tool that returns bare strings instead
        # of proper Finding dicts (e.g. blue_team.canary_token_deployment's
        # real decoy-credential findings) gets normalised by
        # ToolExecutor.run() into `Finding(title=str(f)[:120], ...)` with NO
        # `evidence` populated — the tool's real, legitimately-generated
        # secret-shaped text (a decoy AWS key it deliberately created) then
        # sits unredacted in `title`, the one Finding field this function
        # used to leave untouched, and OutputGuard's independent secret
        # patterns (which cover fields redact_findings() doesn't reach)
        # would otherwise discard the whole result instead of redacting it.
        title = new_item.get("title")
        if isinstance(title, str):
            new_item["title"] = _redact_text(title, extra_patterns)
        out.append(new_item)
    return out
