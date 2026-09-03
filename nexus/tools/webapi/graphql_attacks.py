#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapi.graphql_attacks
Domain: webapi
GraphQL security checks: introspection, batching DoS, and query depth abuse.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
import urllib.parse
import urllib.error
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

INTROSPECTION_QUERY = """{__schema{types{name}}}"""

DEPTH_QUERY = (
    "{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "{__typename{__typename{__typename{__typename{__typename"
    "}"
    "}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}"
)


def _post_graphql(url: str, query: str, timeout: int = 15, variables: dict = None) -> dict:
    """POST a GraphQL query; returns {'status': int, 'body': str, 'time': float}."""
    ctx = get_ssl_context(url, allow_insecure=True)
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "NEXUS-STRIKE/1.0.0 (GraphQL Scanner)",
        },
        method="POST",
    )
    import time
    try:
        t0 = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "time": round(time.time() - t0, 3)}
    except urllib.error.HTTPError as e:
        body = (e.read(65536).decode("utf-8", errors="replace") if e.fp else "") or ""
        return {"status": e.code, "body": body, "time": 0}
    except Exception as exc:
        return {"status": 0, "body": "", "time": 0, "error": str(exc)[:100]}


def _build_batch_query(batch_count: int) -> str:
    """Build a single request containing N aliased introspection queries (batching)."""
    aliases = []
    for i in range(batch_count):
        aliases.append(f'a{i}:__typename{{__typename}}')
    return "{" + " ".join(aliases) + "}"


def run(
    target: str,
    timeout: int = 15,
    depth: int = 50,
    batch_size: int = 100,
    **kwargs: Any,
) -> dict:
    """Probe a GraphQL endpoint for common misconfigurations.

    Parameters
    ----------
    target : str
        GraphQL endpoint URL (e.g. https://example.com/graphql) or a base host.
    timeout : int
        Request timeout in seconds.
    depth : int
        Query depth to test for depth-limit enforcement.
    batch_size : int
        Number of queries to send in a single batching test.
    """
    if not target or not target.strip():
        return tool_result("webapi.graphql_attacks", target, status=STATUS_FAILED, error="Empty target")

    # Normalise target: if no path is given, try /graphql, /graphiql, /v1/graphql
    base = target if "://" in target else f"http://{target}"
    candidates = [base, base.rstrip("/") + "/graphql", base.rstrip("/") + "/graphiql", base.rstrip("/") + "/v1/graphql"]
    endpoints = []
    for cand in candidates:
        if cand not in endpoints:
            endpoints.append(cand)

    findings: list[Finding] = []
    results: list[dict] = []

    # ── Phase 1: Locate endpoint + introspection ─────────────────────────────
    endpoint_found = None
    for ep in endpoints:
        resp = _post_graphql(ep, INTROSPECTION_QUERY, timeout)
        if resp["status"] and resp["status"] != 0:
            body = resp["body"]
            # Check if this is actually a GraphQL response
            if '"data"' in body or '"error' in body or '"errors"' in body:
                endpoint_found = ep
                try:
                    parsed = json.loads(body)
                    data = parsed.get("data") or {}
                    if data.get("__schema", {}).get("types"):
                        findings.append(Finding(
                            title="GraphQL introspection is enabled",
                            severity="medium",
                            confidence="high",
                            affected_asset=ep,
                            evidence=f"Introspection query returned schema types on {ep}",
                            remediation=(
                                "Disable GraphQL introspection in production, or restrict it "
                                "to authenticated admin clients via a middleware."
                            ),
                            tool="webapi.graphql_attacks",
                            references=["CWE-200", "OWASP-API9"],
                        ))
                        results.append({"endpoint": ep, "test": "introspection", "enabled": True})
                    else:
                        results.append({"endpoint": ep, "test": "introspection", "enabled": False})
                except json.JSONDecodeError:
                    results.append({"endpoint": ep, "test": "introspection", "enabled": False})
                break

    if not endpoint_found:
        return tool_result(
            "webapi.graphql_attacks",
            target,
            status=STATUS_NO_FINDINGS,
            findings=[],
            summary="No GraphQL endpoint detected on target",
            metadata={"candidates": endpoints, "results": results},
        )

    # ── Phase 2: Query depth limit ────────────────────────────────────────────
    depth_payload = "{__typename" + ("{__typename" * depth) + ("}" * (depth + 1))
    resp = _post_graphql(endpoint_found, depth_payload, timeout)
    if resp["status"] and resp["status"] != 0:
        if resp["status"] == 400 or "max" in resp["body"].lower() or "depth" in resp["body"].lower():
            results.append({"endpoint": endpoint_found, "test": "depth_limit", "limited": True})
            if "max" in resp["body"].lower() or "depth" in resp["body"].lower():
                findings.append(Finding(
                    title="GraphQL depth limit enforced",
                    severity="info",
                    confidence="high",
                    affected_asset=endpoint_found,
                    evidence=f"Deep query rejected (HTTP {resp['status']})",
                    remediation="No action required — depth limiting is correctly enforced.",
                    tool="webapi.graphql_attacks",
                    references=["OWASP-API4"],
                ))
        else:
            results.append({"endpoint": endpoint_found, "test": "depth_limit", "limited": False})
            # Check for timeout as evidence of CPU exhaustion
            if resp["time"] >= timeout - 2:
                findings.append(Finding(
                    title="GraphQL query depth abuse (possible DoS)",
                    severity="medium",
                    confidence="medium",
                    affected_asset=endpoint_found,
                    evidence=f"Deep query of depth {depth} took {resp['time']}s — depth limit may be missing.",
                    remediation="Implement a query-depth or complexity limit to prevent denial of service.",
                    tool="webapi.graphql_attacks",
                    references=["CWE-400", "OWASP-API4"],
                ))
            else:
                findings.append(Finding(
                    title="GraphQL query depth limit not enforced",
                    severity="medium",
                    confidence="medium",
                    affected_asset=endpoint_found,
                    evidence=f"Deep query of depth {depth} accepted (HTTP {resp['status']})",
                    remediation="Enforce a maximum GraphQL query depth to prevent resource exhaustion.",
                    tool="webapi.graphql_attacks",
                    references=["CWE-400", "OWASP-API4"],
                ))

    # ── Phase 3: Batching (alias) abuse ───────────────────────────────────────
    batch_query = _build_batch_query(batch_size)
    resp = _post_graphql(endpoint_found, batch_query, timeout)
    if resp["status"] and resp["status"] != 0:
        if "a0" in resp["body"] or resp["status"] == 200:
            results.append({"endpoint": endpoint_found, "test": "batching", "allowed": True})
            findings.append(Finding(
                title="GraphQL batching / alias abuse allowed",
                severity="low",
                confidence="medium",
                affected_asset=endpoint_found,
                evidence=f"Single request with {batch_size} batched queries accepted (HTTP {resp['status']})",
                remediation=(
                    "Limit the number of aliases per request and apply rate limiting "
                    "to prevent batching-based brute force or DoS."
                ),
                tool="webapi.graphql_attacks",
                references=["CWE-400", "OWASP-API4"],
            ))
        else:
            results.append({"endpoint": endpoint_found, "test": "batching", "allowed": False})

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"GraphQL scan on {endpoint_found}: {len(findings)} finding(s), {len(results)} test(s)"
    return tool_result(
        "webapi.graphql_attacks",
        target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"endpoint": endpoint_found, "results": results},
    )


tool_registry.register("webapi.graphql_attacks", run, metadata={
    "name": "webapi.graphql_attacks",
    "domain": "webapi",
    "status": "completed",
    "description": "GraphQL security checks: introspection, query depth abuse, and batching DoS",
    "parameters": {
        "target": "GraphQL endpoint URL or base host",
        "timeout": "Request timeout in seconds (default: 15)",
        "depth": "Query depth to test (default: 50)",
        "batch_size": "Number of batched queries to test (default: 100)",
    },
})