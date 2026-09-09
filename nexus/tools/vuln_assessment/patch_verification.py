#!/usr/bin/env python3
"""
NEXUS-STRIKE — vuln_assessment tool: Patch Verification
Domain: vuln_assessment

Real, best-effort patch-currency check: reuses network.banner_grab (a
real, already-implemented domain tool) via tool_registry to detect an
actual software product/version banner on `target`, then — only if the
caller supplies what "latest known good" means via `expected_version` —
does a real version comparison. There is no reliable free, generic
"latest version for any product" API this codebase can call, so
fabricating one (e.g. a hardcoded table of "current" versions that goes
stale the day it's written) would just be a slower-rotting version of the
fake-stub problem this tool is being fixed for. Detection is real; the
comparison step is honest about needing a reference version.

This was previously one of 8 vuln_assessment tools sharing byte-for-byte
identical fake logic (a hardcoded-port TCP scan + bare HTTP GET, unrelated
to patch verification) — caught during this session's audit.
"""
from __future__ import annotations

import re
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "vuln_assessment.patch_verification"
_PRODUCT_RE = re.compile(r"Product:\s*(\S+)")
_VERSION_RE = re.compile(r"Version:\s*(\S+)")


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _detect_versions(target: str) -> list[dict]:
    """Best-effort real detection via network.banner_grab, reused through
    tool_registry rather than duplicated."""
    detected: list[dict] = []
    available = tool_registry.list_tools()
    if "network.banner_grab" not in available:
        return detected
    try:
        result = tool_registry.run("network.banner_grab", target=target)
    except Exception:  # noqa: BLE001 - detection is best-effort, a failure here just means none detected
        return detected
    for f in result.get("findings", []) or []:
        evidence = f.get("evidence", "") or ""
        product_m = _PRODUCT_RE.search(evidence)
        version_m = _VERSION_RE.search(evidence)
        if product_m and version_m:
            detected.append({
                "product": product_m.group(1),
                "version": version_m.group(1),
                "affected_asset": f.get("affected_asset", target),
                "source": "network.banner_grab",
            })
    return detected


def run(target: str, **kwargs: Any) -> dict:
    """Real detection + optional real comparison against an expected version."""
    detected = _detect_versions(target)

    if not detected:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"No software version banner was detected on {target} via network.banner_grab — "
                    f"nothing to patch-verify",
        )

    expected = kwargs.get("expected_version")
    if not expected:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_UNAVAILABLE,
            summary=f"Detected {len(detected)} real version banner(s) on {target}, but no reference "
                    f"'latest known good' version was supplied to compare against",
            error="requires_case_data: pass expected_version='<version string>' (or "
                  "expected_version={'ProductName': '<version>', ...}) — this tool has no reliable "
                  "generic 'latest version for any product' feed to fall back on",
            metadata={"detected_versions": detected},
        )

    expected_map = expected if isinstance(expected, dict) else {d["product"]: expected for d in detected}

    findings: list[Finding] = []
    outdated_count = 0
    for d in detected:
        ref = expected_map.get(d["product"])
        if not ref:
            continue
        outdated = _version_tuple(d["version"]) < _version_tuple(str(ref))
        outdated_count += 1 if outdated else 0
        findings.append(Finding(
            title=f"{d['product']} {d['version']} vs expected {ref}",
            severity="high" if outdated else "info",
            confidence="high",
            affected_asset=d["affected_asset"],
            evidence=f"Detected {d['product']} version {d['version']} (via {d['source']}); expected/"
                     f"latest-known-good is {ref} — {'OUTDATED' if outdated else 'up to date or newer'}",
            remediation=f"Patch {d['product']} to at least version {ref}." if outdated else "No action required.",
            tool=_TOOL_NAME,
            references=["CWE-1104"],
        ))

    if not findings:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"Detected version(s) for {[d['product'] for d in detected]} but expected_version "
                    f"had no matching product key(s) to compare against",
            metadata={"detected_versions": detected},
        )

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Compared {len(findings)} detected version(s) against expected/latest-known-good; "
                f"{outdated_count} outdated",
        metadata={"detected_versions": detected},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "vuln_assessment",
    "status": "completed",
    "description": "Real version detection via network.banner_grab; real comparison against an "
                    "expected/latest-known version when supplied",
    "parameters": {
        "target": "Target IP or hostname",
        "expected_version": "Version string, or {'Product': 'version'} dict, to compare detections against",
    },
})
