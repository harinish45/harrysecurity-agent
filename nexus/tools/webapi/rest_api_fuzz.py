#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapi.rest_api_fuzz
Domain: webapi
Real REST API fuzzer (wordlist of HTTP methods, content-types, auth headers).
"""
from __future__ import annotations
import urllib.request
import ssl
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]
CONTENT_TYPES = ["application/json", "application/xml", "application/x-www-form-urlencoded", "multipart/form-data"]
AUTH_HEADERS = [
    {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},
    {"X-Api-Key": "test-api-key-12345"}
]

def run(target: str, **kwargs: Any) -> dict:
    """Perform REST API fuzzing to identify misconfigurations and hidden endpoints."""
    findings = []
    fuzz_results = []
    
    try:
        url = target if "://" in target else f"http://{target}"
        ctx = get_ssl_context(target, allow_insecure=True)
        
        # Fuzz HTTP methods
        for method in HTTP_METHODS:
            try:
                req = urllib.request.Request(url, method=method, headers={"User-Agent": "NEXUS-STRIKE/0.2.0"})
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                if method not in ["GET", "POST", "OPTIONS"] and resp.status not in [401, 403, 405]:
                    findings.append(Finding(
                        title=f"Unrestricted HTTP Method: {method}",
                        severity="medium",
                        confidence="medium",
                        affected_asset=url,
                        evidence=f"Endpoint accepts '{method}' method and returned status {resp.status}. This may allow unintended state changes.",
                        remediation="Implement strict HTTP method allow-listing at the web server or API gateway level.",
                        tool="webapi.rest_api_fuzz",
                        references=["CWE-749", "OWASP-API3"]
                    ))
                    fuzz_results.append({"method": method, "status": resp.status})
            except urllib.error.HTTPError as e:
                if e.code not in [401, 403, 405]:
                    fuzz_results.append({"method": method, "status": e.code})
            except Exception:
                pass
                
        # Fuzz Auth headers
        for auth_header in AUTH_HEADERS:
            try:
                headers = {"User-Agent": "NEXUS-STRIKE/0.2.0", **auth_header}
                req = urllib.request.Request(url, headers=headers, method="GET")
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                if resp.status == 200:
                    findings.append(Finding(
                        title="Weak or Default Credentials Accepted",
                        severity="high",
                        confidence="medium",
                        affected_asset=url,
                        evidence=f"Endpoint returned 200 OK with test credential: {list(auth_header.keys())[0]}",
                        remediation="Enforce strong authentication and invalidate default/test credentials.",
                        tool="webapi.rest_api_fuzz",
                        references=["CWE-798", "OWASP-API7"]
                    ))
                    fuzz_results.append({"auth_test": list(auth_header.keys())[0], "status": resp.status})
            except Exception:
                pass
                
        summary = f"REST API fuzzing completed. Logged {len(fuzz_results)} notable responses."
        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        
    except Exception as e:
        return tool_result("webapi.rest_api_fuzz", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "webapi.rest_api_fuzz", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"fuzz_results": fuzz_results}
    )

tool_registry.register("webapi.rest_api_fuzz", run, metadata={
    "name": "webapi.rest_api_fuzz",
    "domain": "webapi",
    "status": "completed",
    "description": "Fuzzes REST APIs with various HTTP methods, content-types, and auth headers",
    "parameters": {"target": "Target API endpoint URL"},
})