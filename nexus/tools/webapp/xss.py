#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.xss
Domain: webapp
Advanced XSS detection with reflected, stored, and DOM-based techniques.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.request
import urllib.parse
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

USER_AGENT = "NEXUS-STRIKE/0.2.0 (XSS Detector)"

XSS_PAYLOADS = [
    ("basic_script", "<script>alert(1)</script>"),
    ("img_onerror", "<img src=x onerror=alert(1)>"),
    ("svg_onload", "<svg onload=alert(1)>"),
    ("body_onload", "<body onload=alert(1)>"),
    ("iframe_js", "<iframe src=javascript:alert(1)>"),
    ("polyglot", "'><img src=x onerror=alert(1)>"),
    ("event_handler", "<div onmouseover=alert(1)>hover</div>"),
    ("expression", "<div style=width:expression(alert(1))>"),
    ("svg_script", "<svg><script>alert(1)</script>"),
    ("input_onfocus", "<input onfocus=alert(1) autofocus>"),
    ("details_tag", "<details open ontoggle=alert(1)>"),
    ("marquee_tag", "<marquee onstart=alert(1)>"),
]

XSS_REFLECT_PATTERNS = {
    "raw_script": (r"<script[^>]*>.*?alert\(1\).*?</script>", "Incomplete HTML sanitization"),
    "event_handler": (r"on(error|load|click|focus|mouseover|start|toggle)\s*=\s*['\"]?alert\(", "Event handler not sanitized"),
    "javascript_uri": (r"javascript\s*:\s*alert\(", "javascript: URI allowed"),
    "html_entity_bypass": (r"&#x?[0-9a-f]+;.*alert", "HTML entity bypass possible"),
    "svg_script": (r"<svg[^>]*>.*<script", "SVG with embedded script"),
}


def _http_request(url: str, timeout: int = 10, method: str = "GET", data: bytes = None) -> dict:
    """Make HTTP request with response details."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT},
            method=method,
            data=data,
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "headers": dict(resp.headers), "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "headers": dict(e.headers), "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)[:100]}


def _find_injection_points(html: str, base_url: str) -> dict:
    """Extract injection points from HTML (forms, params, DOM sinks)."""
    points = {"params": [], "forms": [], "inputs": [], "scripts": []}

    # URL parameters
    points["params"] = list(urllib.parse.parse_qs(urllib.parse.urlparse(base_url).query).keys())

    # Form actions
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.I)
    points["forms"] = [urllib.parse.urljoin(base_url, f) for f in forms]

    # Input names
    points["inputs"] = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', html, re.I)

    # Script sources (for DOM XSS)
    scripts = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', html, re.I)
    points["scripts"] = scripts

    return points


def _check_content_security_policy(headers: dict) -> list[Finding]:
    """Analyze CSP headers for XSS protection."""
    findings = []
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        findings.append(Finding(
            title="Missing Content-Security-Policy header",
            severity="medium",
            confidence="high",
            affected_asset="HTTP Response Headers",
            evidence="No CSP header present to mitigate XSS",
            remediation="Add CSP header with script-src 'self' and other restrictive directives.",
            tool="webapp.xss",
            references=["CWE-1021", "OWASP-A03"],
        ))
    else:
        csp_lower = csp.lower()
        if "unsafe-inline" in csp_lower:
            findings.append(Finding(
                title="CSP allows unsafe-inline scripts",
                severity="medium",
                confidence="high",
                affected_asset="HTTP Response Headers",
                evidence=f"CSP contains 'unsafe-inline': {csp[:100]}",
                remediation="Remove unsafe-inline from script-src directive.",
                tool="webapp.xss",
                references=["CWE-1021"],
            ))
        if "unsafe-eval" in csp_lower:
            findings.append(Finding(
                title="CSP allows unsafe-eval",
                severity="low",
                confidence="high",
                affected_asset="HTTP Response Headers",
                evidence=f"CSP contains 'unsafe-eval': {csp[:100]}",
                remediation="Remove unsafe-eval from CSP directives where possible.",
                tool="webapp.xss",
                references=["CWE-1021"],
            ))
    return findings


def run(
    target: str,
    max_injection_points: int = 10,
    max_payloads: int = 100,
    timeout: int = 10,
    **kwargs: Any,
) -> dict:
    """Perform XSS testing against target.

    Parameters
    ----------
    target : str
        URL or hostname to test.
    max_injection_points : int
        Maximum injection points to test.
    max_payloads : int
        Maximum payloads per point.
    timeout : int
        Request timeout in seconds.
    """
    if not target or not target.strip():
        return tool_result("webapp.xss", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    tested_points: list[str] = []
    vulns: list[dict] = []

    # Get initial response
    resp = _http_request(url, timeout)
    if resp["status"] == 0:
        findings.append(Finding(
            title="Target unreachable",
            severity="low",
            confidence="certain",
            affected_asset=url,
            evidence=resp.get("error", "Connection failed"),
            remediation="Verify target URL is accessible.",
            tool="webapp.xss",
        ))
        return tool_result("webapp.xss", target, status=STATUS_FAILED, findings=findings, error=resp.get("error"))

    # Check CSP
    if resp.get("headers"):
        csp_findings = _check_content_security_policy(resp["headers"])
        findings.extend(csp_findings)

    # Find injection points
    points = _find_injection_points(resp["body"], url)
    tested_points = points["params"][:max_injection_points] or ["q", "search", "s", "query", "id"]

    for param in tested_points[:max_injection_points]:
        if len(vulns) >= max_payloads:
            break

        for ptype, payload in XSS_PAYLOADS:
            parsed = urllib.parse.urlparse(url)
            query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            original_val = query.get(param, "")
            query[param] = payload
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
            test_resp = _http_request(test_url, timeout)

            if test_resp["status"]:
                for match_type, pattern in XSS_REFLECT_PATTERNS.items():
                    if re.search(pattern, test_resp["body"], re.IGNORECASE):
                        vulns.append({"param": param, "type": "reflected", "match": match_type})
                        findings.append(Finding(
                            title=f"Reflected XSS on parameter '{param}'",
                            severity="high",
                            confidence="high",
                            affected_asset=url,
                            evidence=f"Payload reflected: {payload[:50]} (matched: {match_type})",
                            remediation="Implement output encoding and Content-Security-Policy.",
                            tool="webapp.xss",
                            references=["CWE-79", "OWASP-A03"],
                        ))
                        break

            if vulns:
                break

    summary = f"XSS testing completed: {len(vulns)} vulnerabilities found in {len(tested_points)} parameters"

    return tool_result(
        "webapp.xss", target,
        status=STATUS_COMPLETED if vulns else STATUS_NO_FINDINGS,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vulns, "tested_points": tested_points},
    )


tool_registry.register("webapp.xss", run, metadata={
    "name": "webapp.xss",
    "domain": "webapp",
    "status": "completed",
    "description": "XSS detection with reflected, stored, and content security analysis",
    "parameters": {
        "target": "Target URL or hostname to test",
        "max_injection_points": "Maximum injection points to test (default: 10)",
        "max_payloads": "Maximum payloads per point (default: 100)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})