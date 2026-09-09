#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.rest_api_testing
Domain: webapp
REST API surface discovery.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", never probed for API structure).
Now: real GETs of common REST API discovery/documentation paths
(/api, /api/v1, /swagger.json, /openapi.json, ...) plus a real HTTP
OPTIONS request against the target root to enumerate allowed methods via
the ``Allow`` response header, flagging exposed API documentation and
risky methods (TRACE, PUT, DELETE, CONNECT) advertised without further
context.
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (REST API Discovery)"

DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/docs",
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/.well-known/openapi.json",
]

RISKY_METHODS = {"TRACE", "CONNECT", "PUT", "DELETE"}


def _http_request(url: str, timeout: int = 10, method: str = "GET") -> dict:
    """Make a real HTTP request and return status/headers/body."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method=method)
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(16384).decode("utf-8", errors="replace") if method != "OPTIONS" else ""
        return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()}, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(16384).decode("utf-8", errors="replace") if e.fp and method != "OPTIONS" else ""
        return {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()}, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)[:100]}


def run(target: str, timeout: int = 10, paths: list[str] | None = None, **kwargs: Any) -> dict:
    """Discover REST API structure via common paths and an OPTIONS probe.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    paths : list[str], optional
        Custom list of discovery paths.
    """
    if not target or not target.strip():
        return tool_result("webapp.rest_api_testing", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []
    discovered: list[dict] = []

    for path in (paths or DISCOVERY_PATHS):
        endpoint = f"{root}{path}"
        resp = _http_request(endpoint, timeout)
        if resp["status"] and resp["status"] not in (0, 404):
            is_doc = path.endswith((".json", ".yaml")) or "swagger" in path or "openapi" in path or "api-docs" in path
            is_spec = False
            if is_doc:
                try:
                    parsed_body = json.loads(resp["body"])
                    is_spec = isinstance(parsed_body, dict) and ("swagger" in parsed_body or "openapi" in parsed_body or "paths" in parsed_body)
                except Exception:
                    is_spec = "swagger" in resp["body"].lower()[:2000] or "openapi" in resp["body"].lower()[:2000]

            discovered.append({"path": path, "url": endpoint, "status": resp["status"], "is_api_spec": is_spec})
            severity = "medium" if is_spec else "low"
            findings.append(Finding(
                title=f"API {'specification' if is_spec else 'path'} exposed: {path}",
                severity=severity,
                confidence="high" if is_spec else "medium",
                affected_asset=endpoint,
                evidence=f"HTTP {resp['status']} at {endpoint}" + (" — parsed as a Swagger/OpenAPI document" if is_spec else ""),
                remediation="Ensure API documentation/specs are not publicly reachable in production, or contain no sensitive internal details.",
                tool="webapp.rest_api_testing",
                references=["CWE-200"] if is_spec else [],
            ))

    options_resp = _http_request(root, timeout, method="OPTIONS")
    allowed_methods: list[str] = []
    if options_resp["status"] and options_resp["status"] != 0:
        allow_header = options_resp["headers"].get("allow", "")
        allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
        risky = sorted(set(allowed_methods) & RISKY_METHODS)
        if risky:
            findings.append(Finding(
                title=f"Potentially risky HTTP method(s) allowed: {', '.join(risky)}",
                severity="medium",
                confidence="high",
                affected_asset=root,
                evidence=f"OPTIONS {root} -> Allow: {allow_header}",
                remediation="Disable HTTP methods that aren't required (TRACE, CONNECT, and unauthenticated PUT/DELETE in particular).",
                tool="webapp.rest_api_testing",
                references=["CWE-650"],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"REST API discovery: {len(discovered)} path(s) found, methods allowed: {allowed_methods or 'unknown (OPTIONS not supported)'}"

    return tool_result(
        "webapp.rest_api_testing", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"discovered": discovered, "allowed_methods": allowed_methods},
    )


tool_registry.register("webapp.rest_api_testing", run, metadata={
    "name": "webapp.rest_api_testing",
    "domain": "webapp",
    "status": "completed",
    "description": "REST API surface discovery via common documentation paths plus an OPTIONS method-enumeration probe",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "paths": "Custom list of discovery paths",
    },
})
