#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Risk Scoring
Domain: vuln_assessment

Real, deterministic CVSS v3.1 Base Score implementation (FIRST.org's
published formula — https://www.first.org/cvss/v3.1/specification-document
section 7.4), computed from a CVSS vector string. Given a target/kwarg
that isn't a CVSS vector, this honestly says it has nothing to score
rather than inventing a number.

This was previously one of 8 vuln_assessment tools sharing byte-for-byte
identical fake logic (a hardcoded-port TCP scan + bare HTTP GET, unrelated
to risk scoring) — caught during this session's audit.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "vuln_assessment.risk_scoring"

# CVSS v3.1 base metric weights (FIRST.org spec §7.1-7.3)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
# Privileges Required depends on Scope (§7.1 Table 3)
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_cvss31_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS:3.1 (or 3.0) vector string into its base metric dict."""
    v = vector.strip()
    upper = v.upper()
    if upper.startswith("CVSS:3.1/") or upper.startswith("CVSS:3.0/"):
        v = v.split("/", 1)[1]
    metrics: dict[str, str] = {}
    for part in v.split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metrics[key.strip().upper()] = val.strip().upper()
    missing = [m for m in _REQUIRED_METRICS if m not in metrics]
    if missing:
        raise ValueError(f"CVSS vector missing required base metric(s): {', '.join(missing)}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS spec's 'Roundup' function (Appendix A) — rounds UP to the
    nearest 0.1 using integer arithmetic so ordinary float rounding never
    silently drops a score like 4.0000000001 to 4.0 (or the reverse)."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (int_value // 10000 + 1) / 10.0


def _rating_for(score: float) -> str:
    if score <= 0.0:
        return "info"  # CVSS "None" maps to this schema's "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def cvss31_base_score(vector: str) -> dict[str, Any]:
    """Compute the real CVSS v3.1 base score for a vector string."""
    metrics = parse_cvss31_vector(vector)

    scope = metrics["S"]
    if scope not in ("U", "C"):
        raise ValueError(f"Invalid Scope value {metrics['S']!r} (expected U or C)")

    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = _PR[scope][metrics["PR"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"Invalid CVSS metric value: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    return {
        "base_score": base_score,
        "severity": _rating_for(base_score),
        "impact_subscore": round(impact, 3),
        "exploitability_subscore": round(exploitability, 3),
        "metrics": metrics,
    }


def run(target: str, **kwargs: Any) -> dict:
    """Compute a real CVSS 3.1 base score from a vector string."""
    vector = kwargs.get("cvss_vector") or (target if target.strip().upper().startswith("CVSS:3") else None)

    if not vector:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_OUT_OF_SCOPE,
            summary="Risk scoring computes a real CVSS 3.1 base score from a vector string, but no "
                    "vector was supplied",
            error="pass cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', or set target "
                  "itself to a CVSS:3.x vector string — no vector was found to score",
        )

    try:
        result = cvss31_base_score(vector)
    except ValueError as exc:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED,
                            error=f"Could not parse/score CVSS vector: {exc}")

    finding = Finding(
        title=f"CVSS 3.1 base score {result['base_score']} ({result['severity']})",
        severity=result["severity"],
        confidence="certain",
        affected_asset=target,
        evidence=f"Vector {vector} — impact subscore {result['impact_subscore']}, exploitability "
                 f"subscore {result['exploitability_subscore']}, base score {result['base_score']} "
                 f"(computed via the published CVSS v3.1 formula)",
        tool=_TOOL_NAME,
        references=["https://www.first.org/cvss/v3.1/specification-document"],
    )

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=[finding],
        summary=f"CVSS 3.1 base score for {vector}: {result['base_score']} ({result['severity']})",
        metadata=result,
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "Real, deterministic CVSS v3.1 base-score calculator from a CVSS vector string",
    "parameters": {
        "target": "A CVSS:3.x vector string, or any label if cvss_vector is passed instead",
        "cvss_vector": "CVSS:3.1 vector string, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'",
    },
})
