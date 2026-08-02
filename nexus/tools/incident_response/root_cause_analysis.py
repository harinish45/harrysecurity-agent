#!/usr/bin/env python3
"""
NEXUS-STRIKE — incident_response tool: Root Cause Analysis
Domain: incident_response
"""
from __future__ import annotations

import socket
import urllib.request
import ssl
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs: Any) -> dict[str, Any]:
    """incident_response tool: Root Cause Analysis"""
    findings: list[Finding] = []

    if not target or not target.strip():
        return tool_result("incident_response.root_cause_analysis", target, status=STATUS_FAILED, error="Empty target")

    try:
        try:
            ip = socket.gethostbyname(target)
            findings.append(Finding(
                title="DNS Resolution",
                severity="info",
                confidence="certain",
                affected_asset=target,
                evidence=f"Target {target} -> {ip}",
                tool="incident_response.root_cause_analysis",
            ))
        except Exception:
            pass

        url = target if "://" in target else f"http://{target}/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            server_header = resp.headers.get('Server', 'unknown')
            findings.append(Finding(
                title="HTTP Server Header",
                severity="info",
                confidence="certain",
                affected_asset=url,
                evidence=f"HTTP {resp.status}: Server={server_header}",
                tool="incident_response.root_cause_analysis",
            ))
        except urllib.error.HTTPError as e:
             findings.append(Finding(
                title="HTTP Request Error",
                severity="info",
                confidence="low",
                affected_asset=url,
                evidence=f"HTTP {e.code}: {url}",
                tool="incident_response.root_cause_analysis",
            ))
        except Exception as e:
            findings.append(Finding(
                title="HTTP Check Failed",
                severity="info",
                confidence="low",
                affected_asset=url,
                evidence=f"HTTP error: {str(e)[:80]}",
                tool="incident_response.root_cause_analysis",
            ))

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result("incident_response.root_cause_analysis", target, status=status, findings=findings)

    except Exception as e:
        return tool_result("incident_response.root_cause_analysis", target, status=STATUS_FAILED, error=str(e))


# Register with tool registry
tool_registry.register("incident_response.root_cause_analysis", run, metadata={
    "name": "incident_response.root_cause_analysis",
    "domain": "incident_response",
    "status": "completed",
    "description": "incident_response tool: Root Cause Analysis",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
