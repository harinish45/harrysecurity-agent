#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.rate_limit
Domain: webapp
Rate-limiting absence detection via a timed request burst.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", a single request — structurally
incapable of ever detecting a rate limit). Now: a real burst of ~20
requests fired against target in a short window, recording each real
response's status code and latency; the absence of any 429/503-with-
Retry-After response, and of any latency degradation typical of
throttling, across the whole burst is flagged as a missing rate-limiting
control.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import time
import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Rate Limit Prober)"

RATE_LIMIT_STATUS_CODES = {429, 503}


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET, returning status and elapsed time."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        resp.read(1024)
        elapsed = time.time() - t0
        return {"status": resp.status, "elapsed": elapsed, "headers": dict(resp.headers), "error": None}
    except urllib.error.HTTPError as e:
        elapsed = time.time() - t0
        return {"status": e.code, "elapsed": elapsed, "headers": dict(e.headers or {}), "error": None}
    except Exception as e:
        elapsed = time.time() - t0
        return {"status": 0, "elapsed": elapsed, "headers": {}, "error": str(e)[:100]}


def run(target: str, burst_size: int = 20, timeout: int = 10, **kwargs: Any) -> dict:
    """Send a timed request burst to detect absence of rate limiting.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    burst_size : int
        Number of requests to fire in the burst.
    timeout : int
        Per-request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.rate_limit", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    results: list[dict] = []

    burst_start = time.time()
    for _ in range(max(1, burst_size)):
        results.append(_http_request(url, timeout))
    burst_elapsed = time.time() - burst_start

    successful = [r for r in results if r["status"] != 0]
    if not successful:
        return tool_result("webapp.rate_limit", target, status=STATUS_FAILED, error="All burst requests failed to connect")

    throttled = [r for r in successful if r["status"] in RATE_LIMIT_STATUS_CODES]
    has_retry_after = any("retry-after" in {k.lower() for k in r["headers"]} for r in successful)
    latencies = [r["elapsed"] for r in successful]
    first_half_avg = sum(latencies[: len(latencies) // 2 or 1]) / (len(latencies) // 2 or 1)
    second_half_avg = sum(latencies[len(latencies) // 2:]) / max(len(latencies) - len(latencies) // 2, 1)
    latency_degraded = second_half_avg > first_half_avg * 2 and second_half_avg > 0.5

    if throttled:
        summary = (
            f"Rate limiting detected: {len(throttled)}/{len(successful)} of {burst_size} burst requests "
            f"were throttled (HTTP {sorted({r['status'] for r in throttled})}) within {burst_elapsed:.2f}s"
        )
        status = STATUS_NO_FINDINGS  # protective control present — nothing to flag
    else:
        findings.append(Finding(
            title="No rate limiting observed under request burst",
            severity="medium" if not latency_degraded else "low",
            confidence="medium",
            affected_asset=url,
            evidence=(
                f"{len(successful)}/{burst_size} requests sent in {burst_elapsed:.2f}s all returned non-throttling "
                f"status codes ({sorted({r['status'] for r in successful})}); no 429/503 or Retry-After header seen"
                + ("; some latency degradation observed but no explicit throttling response" if latency_degraded else "")
            ),
            remediation="Implement per-IP/per-account rate limiting (e.g. 429 responses with Retry-After) on this endpoint, particularly for authentication and expensive operations.",
            tool="webapp.rate_limit",
            references=["CWE-770", "OWASP-API4"],
        ))
        status = STATUS_COMPLETED
        summary = (
            f"Rate limiting NOT detected: {len(successful)}/{burst_size} requests in {burst_elapsed:.2f}s, "
            f"no throttling status codes observed"
        )

    return tool_result(
        "webapp.rate_limit", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={
            "burst_size": burst_size,
            "burst_elapsed_s": round(burst_elapsed, 3),
            "successful_requests": len(successful),
            "throttled_requests": len(throttled),
            "has_retry_after_header": has_retry_after,
            "avg_latency_first_half_s": round(first_half_avg, 3),
            "avg_latency_second_half_s": round(second_half_avg, 3),
            "status_codes_seen": sorted({r["status"] for r in successful}),
        },
    )


tool_registry.register("webapp.rate_limit", run, metadata={
    "name": "webapp.rate_limit",
    "domain": "webapp",
    "status": "completed",
    "description": "Rate-limiting absence detection via a timed burst of requests, measuring real response codes and latency",
    "parameters": {
        "target": "Target URL or hostname to test",
        "burst_size": "Number of requests to fire in the burst (default: 20)",
        "timeout": "Per-request timeout in seconds (default: 10)",
    },
})
