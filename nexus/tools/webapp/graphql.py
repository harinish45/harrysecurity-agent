#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.graphql
Domain: webapp
GraphQL endpoint discovery and introspection exposure detection.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", never even looked for a GraphQL
endpoint). Now: real POSTs of a standard GraphQL introspection query
against common GraphQL endpoint paths, flagging any endpoint that returns
a populated ``__schema`` — a real, high-value information-disclosure
finding since introspection exposes the entire API surface (types,
mutations, fields) to an unauthenticated caller.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import json
import urllib.error
import urllib.request
import urllib.parse
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (GraphQL Prober)"

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/graphql/console",
    "/graphiql", "/gql", "/api/gql", "/query",
]

INTROSPECTION_QUERY = json.dumps({
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }"
}).encode("utf-8")


def _post_json(url: str, payload: bytes, timeout: int = 10) -> dict:
    """Make a real HTTP POST with a JSON body and return status/body."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(131072).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(131072).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)[:100]}


def run(target: str, timeout: int = 10, paths: list[str] | None = None, **kwargs: Any) -> dict:
    """Discover GraphQL endpoints and test whether introspection is enabled.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    paths : list[str], optional
        Custom list of GraphQL endpoint paths to try.
    """
    if not target or not target.strip():
        return tool_result("webapp.graphql", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []
    endpoints_found: list[dict] = []
    introspection_enabled: list[str] = []

    for path in (paths or GRAPHQL_PATHS):
        endpoint = f"{root}{path}"
        resp = _post_json(endpoint, INTROSPECTION_QUERY, timeout)
        if resp["status"] == 0 or resp["status"] == 404:
            continue

        try:
            data = json.loads(resp["body"])
        except Exception:
            data = None

        is_graphql = isinstance(data, dict) and ("data" in data or "errors" in data)
        if not is_graphql:
            continue

        endpoints_found.append({"url": endpoint, "status": resp["status"]})
        findings.append(Finding(
            title=f"GraphQL endpoint discovered: {endpoint}",
            severity="info",
            confidence="high",
            affected_asset=endpoint,
            evidence=f"HTTP {resp['status']} with a GraphQL-shaped JSON response body",
            remediation="Confirm this endpoint should be reachable; restrict/authenticate it if unintended.",
            tool="webapp.graphql",
            references=[],
        ))

        schema = (data or {}).get("data", {}).get("__schema") if isinstance(data, dict) else None
        if schema and schema.get("types"):
            introspection_enabled.append(endpoint)
            type_count = len(schema.get("types", []))
            findings.append(Finding(
                title=f"GraphQL introspection is ENABLED at {endpoint}",
                severity="high",
                confidence="high",
                affected_asset=endpoint,
                evidence=f"Introspection query returned {type_count} type(s), queryType={schema.get('queryType')}, mutationType={schema.get('mutationType')}",
                remediation="Disable introspection in production (e.g. NoSchemaIntrospectionCustomRule in graphql-js, or introspection=False in Graphene/Ariadne).",
                tool="webapp.graphql",
                references=["CWE-200", "OWASP-API9"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"GraphQL probing: {len(endpoints_found)} endpoint(s) found, {len(introspection_enabled)} with introspection enabled" \
        if endpoints_found else "GraphQL probing: no GraphQL endpoint found at common paths"

    return tool_result(
        "webapp.graphql", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"endpoints_found": endpoints_found, "introspection_enabled": introspection_enabled},
    )


tool_registry.register("webapp.graphql", run, metadata={
    "name": "webapp.graphql",
    "domain": "webapp",
    "status": "completed",
    "description": "GraphQL endpoint discovery via common paths, plus real introspection-query probing for schema disclosure",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "paths": "Custom list of GraphQL endpoint paths to try",
    },
})
