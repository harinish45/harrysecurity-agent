#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.rfi
Domain: webapp
Remote File Inclusion (RFI) detection via passive-shaped URL-parameter probes.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no RFI-shaped payloads at all).
Now: real GETs with file-inclusion-style parameters set to remote-URL and
wrapper-style values (never an attacker-controlled callback host — this is
non-destructive/passive detection, not a live RFI proof-of-concept), and
inspection of each response for indicators that the application actually
attempted to fetch/include a remote resource: PHP's
``allow_url_include``/``allow_url_fopen`` error strings, "failed to open
stream: HTTP request failed", wrapper-disabled errors, and reflection of
the injected URL/scheme back in an include-related error message.
"""
from __future__ import annotations
from nexus.foundation.net import safe_urlopen

import re
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (RFI Detector)"

# Non-destructive: these point at benign/nonexistent marker resources, not
# an attacker-controlled callback server. We are only checking whether the
# *application itself* leaks that it tried to fetch/include them.
RFI_PAYLOADS = [
    "http://example.com/nexus-strike-rfi-marker.txt",
    "https://example.com/nexus-strike-rfi-marker.txt",
    "//example.com/nexus-strike-rfi-marker.txt",
    "http://example.com/nexus-strike-rfi-marker.txt%00",
    "php://filter/convert.base64-encode/resource=index",
    "data://text/plain;base64,bmV4dXMtc3RyaWtl",
]

RFI_SIGNATURES = [
    (r"failed to open stream.*(http|https)", "PHP include() attempted to fetch a remote stream"),
    (r"allow_url_include", "PHP allow_url_include reference leaked in error"),
    (r"allow_url_fopen", "PHP allow_url_fopen reference leaked in error"),
    (r"http:// wrapper is disabled", "Remote wrapper explicitly disabled (confirms wrapper handling exists)"),
    (r"nexus-strike-rfi-marker", "Injected marker URL reflected back from an include/fetch attempt"),
    (r"failed to open stream: no suitable wrapper", "Wrapper resolution attempted on injected scheme"),
    (r"getimagesize\(\).*http", "Remote URL passed to a file-reading function"),
]


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make a real HTTP GET and return status/body."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = get_ssl_context(url, allow_insecure=True)
        resp = safe_urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)[:100]}


def _inject_url(target: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(target)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = payload
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


def run(target: str, max_params: int = 10, timeout: int = 10, **kwargs: Any) -> dict:
    """Test target for Remote File Inclusion indicators.

    Parameters
    ----------
    target : str
        Target URL to test.
    max_params : int
        Maximum parameters to test.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.rfi", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    vulns: list[dict] = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        params = {"file": "test", "page": "test", "include": "test", "template": "test", "module": "test", "lang": "en"}

    tested_params = list(params.keys())[:max_params]

    for param in tested_params:
        for payload in RFI_PAYLOADS:
            test_url = _inject_url(url, param, payload)
            resp = _http_request(test_url, timeout)
            if resp["status"] and resp["status"] != 0:
                for pattern, desc in RFI_SIGNATURES:
                    if re.search(pattern, resp["body"], re.IGNORECASE):
                        vulns.append({"param": param, "payload": payload, "signature": desc})
                        findings.append(Finding(
                            title=f"Remote File Inclusion indicator on parameter '{param}'",
                            severity="critical",
                            confidence="medium",
                            affected_asset=url,
                            evidence=f"Payload: {payload[:60]} matched: {desc}",
                            remediation="Disable allow_url_include/allow_url_fopen; never pass user input into include()/require()/file-read functions.",
                            tool="webapp.rfi",
                            references=["CWE-98", "OWASP-A03"],
                        ))
                        break
            if vulns:
                break
        if vulns:
            break

    status = STATUS_COMPLETED if vulns else STATUS_NO_FINDINGS
    summary = f"RFI testing completed on {len(tested_params)} parameter(s)"
    if vulns:
        summary += f" — {len(vulns)} indicator(s) found"

    return tool_result(
        "webapp.rfi", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vulns, "tested_params": tested_params},
    )


tool_registry.register("webapp.rfi", run, metadata={
    "name": "webapp.rfi",
    "domain": "webapp",
    "status": "completed",
    "description": "Remote File Inclusion detection via passive-shaped marker-URL parameter probes",
    "parameters": {
        "target": "Target URL to test",
        "max_params": "Maximum parameters to test (default: 10)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})
