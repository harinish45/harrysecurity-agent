#!/usr/bin/env python3
"""
NEXUS-STRIKE — ai_security.adversarial_ml
Domain: ai_security

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to adversarial ML at
all). Caught during a follow-up audit. Now probes `target` for the same
ML-model-serving-API-shaped endpoints as model_extraction_testing.py
(reused here rather than duplicated), then checks a real, adjacent
signal: whether the API exposes raw class scores/logits — the exact
gradient-free feedback an attacker needs to iteratively craft adversarial
examples (small input perturbations that flip a model's classification).
Honest no_findings when no such endpoint is reachable.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.ai_security.llm_prompt_injection_testing import _probe_endpoint
from nexus.tools.ai_security.model_extraction_testing import (
    _MODEL_ENDPOINT_PATHS,
    _probe_confidence_leak,
)
from nexus.tools.registry import tool_registry

_TOOL_NAME = "ai_security.adversarial_ml"


def run(target: str, **kwargs: Any) -> dict:
    """Probe for a classification API and check for raw score/logit exposure that would ease adversarial-example crafting."""
    target = (target or "").strip()
    if not target:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error="Empty target")

    try:
        live_endpoints = []
        for path in _MODEL_ENDPOINT_PATHS:
            result = _probe_endpoint(target, path)
            if result is not None:
                live_endpoints.append(result)
    except Exception as e:
        return tool_result(_TOOL_NAME, target, status=STATUS_FAILED, error=f"endpoint discovery failed: {e}")

    if not live_endpoints:
        return tool_result(
            _TOOL_NAME, target, status=STATUS_NO_FINDINGS,
            summary=f"No classification/model-serving API found on {target} — adversarial example crafting "
                    f"requires query access to a live classifier, which was not found "
                    f"(checked {len(_MODEL_ENDPOINT_PATHS)} known serving-API paths)",
        )

    findings: list[Finding] = []
    for endpoint in live_endpoints:
        url = endpoint["url"]
        findings.append(Finding(
            title=f"Queryable classification endpoint found: {url}",
            severity="info",
            confidence="medium",
            affected_asset=url,
            evidence=f"status={endpoint['status']}, Content-Type={endpoint['content_type'] or 'unknown'}",
            remediation="Confirm this classification endpoint is intentionally exposed for untrusted query access.",
            tool=_TOOL_NAME,
            references=["CWE-200"],
        ))
        attempted, detail = _probe_confidence_leak(url)
        if attempted:
            leaked = "score-shaped keys" in detail
            findings.append(Finding(
                title=f"Adversarial-crafting feedback-channel check on {url}",
                severity="medium" if leaked else "info",
                confidence="medium" if leaked else "low",
                affected_asset=url,
                evidence=(
                    f"{detail} — raw scores/logits give an attacker a continuous optimization signal "
                    "for iteratively perturbing inputs (e.g. FGSM/PGD-style attacks) until the "
                    "classification flips, far more efficiently than a bare top-1 label would."
                    if leaked else detail
                ),
                remediation="Return only the top predicted label (not raw scores/logits) to untrusted "
                            "callers, add input validation/anomaly detection for out-of-distribution "
                            "queries, and consider adversarial training or gradient masking as defense-in-depth.",
                tool=_TOOL_NAME,
                references=["CWE-200", "https://owasp.org/www-project-machine-learning-security-top-10/"],
            ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Found {len(live_endpoints)} candidate classification endpoint(s) on {target}",
        metadata={"endpoints": [e["url"] for e in live_endpoints]},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "ai_security",
    "status": "completed",
    "description": "Probes for live classification/model-serving endpoints and checks for real raw "
                    "score/logit exposure — the feedback signal that eases adversarial-example crafting",
    "parameters": {
        "target": "Target domain, IP, or URL hosting a classification API",
    },
})
