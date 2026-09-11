#!/usr/bin/env python3
"""
NEXUS-STRIKE — ai_security.model_extraction_testing
Domain: ai_security

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to model extraction at
all). Caught during a follow-up audit. Now probes `target` for common
ML-model-serving-API-shaped endpoints (TensorFlow Serving, TorchServe,
MLflow, generic `/predict`), and when one responds, makes a best-effort
check of whether it leaks raw confidence/probability/logit values — the
real signal that makes model extraction (rebuilding a model's decision
boundary via repeated queries) practical — and whether any rate limiting
is observable across a short burst of requests.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.ai_security.llm_prompt_injection_testing import _probe_endpoint
from nexus.tools.registry import tool_registry

_TOOL_NAME = "ai_security.model_extraction_testing"
_USER_AGENT = "NEXUS-STRIKE/0.2.0 (ModelExtractionTesting)"

# Common ML-model-serving-API-shaped paths across the major serving stacks.
_MODEL_ENDPOINT_PATHS = [
    "/v1/models/model:predict",     # TensorFlow Serving REST
    "/v1/models/model:classify",    # TensorFlow Serving REST
    "/v1/models/model/versions/1:predict",
    "/predictions/model",           # TorchServe
    "/invocations",                 # MLflow / SageMaker-style
    "/predict", "/api/predict", "/v1/predict",  # generic
]

_SCORE_KEYWORDS = ("probability", "probabilities", "confidence", "logit", "logits", "score", "scores")


def _probe_confidence_leak(url: str, timeout: int = 6) -> tuple[bool, str]:
    """Best-effort: POST a minimal generic payload and check whether the
    raw response body contains score/probability/logit-shaped keys. The
    target's real input schema is unknown without documentation, so this
    is a single conservative attempt — a failure just means "could not
    confirm," not "not vulnerable." Returns (attempted, detail)."""
    payload = json.dumps({"instances": [[0.0]], "inputs": [[0.0]]}).encode("utf-8")
    try:
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"User-Agent": _USER_AGENT, "Content-Type": "application/json"},
        )
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(8192).decode("utf-8", errors="replace")
        lowered = body.lower()
        hits = [kw for kw in _SCORE_KEYWORDS if kw in lowered]
        if hits:
            return True, f"response body contains score-shaped keys ({', '.join(hits)}) — raw confidence/probability output detected"
        return True, "endpoint responded but no score/probability-shaped keys observed in the body — inconclusive"
    except urllib.error.HTTPError as e:
        return True, f"endpoint rejected the probe request (HTTP {e.code}) — could not inspect response body"
    except Exception as e:
        return False, f"could not complete confidence-leak probe: {e}"


def _check_rate_limiting(url: str, attempts: int = 5, timeout: int = 5) -> str:
    """Fire a short burst of requests and note whether the server pushes
    back (429, or increasing latency) — a real signal for whether
    high-volume extraction queries would be throttled."""
    statuses = []
    start = time.monotonic()
    for _ in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="GET")
            ctx = get_ssl_context(url, allow_insecure=True)
            resp = safe_urlopen(req, timeout=timeout, context=ctx)
            statuses.append(resp.status)
        except urllib.error.HTTPError as e:
            statuses.append(e.code)
        except Exception:
            statuses.append(None)
    elapsed = time.monotonic() - start
    if 429 in statuses:
        return f"observed HTTP 429 during a {attempts}-request burst ({elapsed:.2f}s) — rate limiting appears to be in place"
    return f"no HTTP 429 observed during a {attempts}-request burst ({elapsed:.2f}s) — no rate limiting detected (best-effort, short sample)"


def run(target: str, **kwargs: Any) -> dict:
    """Probe for ML-model-serving endpoints and check for confidence/probability leakage that would ease model extraction."""
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
            summary=f"No common ML-model-serving-API-shaped endpoints found on {target} "
                    f"(checked {len(_MODEL_ENDPOINT_PATHS)} known paths for TensorFlow Serving, "
                    f"TorchServe, MLflow, and generic /predict conventions)",
        )

    findings: list[Finding] = []
    for endpoint in live_endpoints:
        url = endpoint["url"]
        findings.append(Finding(
            title=f"Possible ML model-serving endpoint found: {url}",
            severity="info",
            confidence="medium",
            affected_asset=url,
            evidence=f"status={endpoint['status']}, Content-Type={endpoint['content_type'] or 'unknown'}",
            remediation="Confirm this model-serving endpoint is intentionally exposed and access-controlled.",
            tool=_TOOL_NAME,
            references=["CWE-200"],
        ))
        attempted, detail = _probe_confidence_leak(url)
        if attempted:
            leaked = "score-shaped keys" in detail
            findings.append(Finding(
                title=f"Confidence/probability leakage check on {url}",
                severity="medium" if leaked else "info",
                confidence="medium" if leaked else "low",
                affected_asset=url,
                evidence=detail,
                remediation="Return only the top predicted label (not raw probabilities/logits) to untrusted "
                            "callers, and rate-limit prediction queries to slow down extraction attacks.",
                tool=_TOOL_NAME,
                references=["CWE-200", "https://owasp.org/www-project-machine-learning-security-top-10/"],
            ))
        rl_detail = _check_rate_limiting(url)
        findings.append(Finding(
            title=f"Rate-limiting observation for {url}",
            severity="low" if "no rate limiting detected" in rl_detail else "info",
            confidence="low",
            affected_asset=url,
            evidence=rl_detail,
            remediation="Apply per-client rate limiting on prediction endpoints to raise the cost of "
                        "high-volume model-extraction query campaigns.",
            tool=_TOOL_NAME,
            references=["CWE-799"],
        ))

    return tool_result(
        _TOOL_NAME, target, status=STATUS_COMPLETED, findings=findings,
        summary=f"Found {len(live_endpoints)} candidate model-serving endpoint(s) on {target}",
        metadata={"endpoints": [e["url"] for e in live_endpoints]},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "ai_security",
    "status": "completed",
    "description": "Probes for live ML-model-serving endpoints (TF Serving/TorchServe/MLflow/generic) and "
                    "checks for real confidence/probability leakage and observable rate limiting — both "
                    "genuine model-extraction risk signals",
    "parameters": {
        "target": "Target domain, IP, or URL hosting a model-serving API",
    },
})
