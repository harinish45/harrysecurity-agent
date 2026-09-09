#!/usr/bin/env python3
"""
NEXUS-STRIKE — ot_ics.scada_security
Domain: ot_ics

Previously checked real port reachability but never inspected anything
SCADA/HMI-specific (byte-for-byte identical to industrial_protocol_reviews.py,
plc_testing.py, modbus_analysis.py, dnp3_testing.py before this fix) —
caught during this session's audit.

Now: real checks focused on the SCADA/HMI supervisory layer specifically
(distinct from ot_ics.plc_testing's field-device focus and
ot_ics.historian_analysis's data-archive focus): a real HTTP GET against
common HMI web-interface ports to detect an exposed, potentially
unauthenticated SCADA web HMI (checking the response for a 200 with no
auth challenge vs a 401/403), plus real port checks for the DNP3/IEC-104
SCADA-to-field-device protocols.
"""
from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_HMI_WEB_PORTS = [80, 443, 8080, 8443]
_SCADA_PROTOCOL_PORTS = [("DNP3", 20000), ("IEC-60870-5-104", 2404)]
_USER_AGENT = "NEXUS-STRIKE/0.2.0 (SCADASecurity)"


def _probe_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _check_hmi_web(host: str, port: int, timeout: float) -> dict | None:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        resp = safe_urlopen(req, timeout=timeout)
        body_preview = resp.read(512).decode("utf-8", errors="ignore")
        return {"url": url, "status": resp.status, "body_preview": body_preview[:200]}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "body_preview": ""}
    except Exception:
        return None


def run(target: str, timeout: float = 3.0, **kwargs: Any) -> dict:
    """Real SCADA/HMI-layer checks: exposed HMI web interface + DNP3/IEC-104 port reachability."""
    host = target.strip()
    if not host:
        return tool_result("ot_ics.scada_security", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    hmi_results: dict[int, dict] = {}
    protocol_results: dict[str, dict] = {}

    for port in _HMI_WEB_PORTS:
        result = _check_hmi_web(host, port, timeout)
        if result is None:
            continue
        hmi_results[port] = result
        auth_keywords = ("login", "password", "unauthorized", "sign in")
        looks_unauthenticated = result["status"] == 200 and not any(
            kw in result["body_preview"].lower() for kw in auth_keywords
        )
        findings.append(Finding(
            title=f"HMI/SCADA web interface reachable at {result['url']} "
                  f"({'no auth prompt detected' if looks_unauthenticated else 'auth-shaped or non-200 response'})",
            severity="critical" if looks_unauthenticated else "medium",
            confidence="high" if looks_unauthenticated else "medium",
            affected_asset=result["url"],
            evidence=f"HTTP {result['status']}; body preview: {result['body_preview']!r}",
            remediation="Require authentication on all SCADA/HMI web interfaces; do not expose "
                        "them outside the OT network. If a login page is expected, verify it "
                        "isn't bypassable and uses strong credentials.",
            tool="ot_ics.scada_security",
            references=["IEC-62443-3-3", "CWE-306"],
        ))

    for name, port in _SCADA_PROTOCOL_PORTS:
        is_open = _probe_port(host, port, timeout)
        protocol_results[name] = {"port": port, "open": is_open}
        if is_open:
            findings.append(Finding(
                title=f"{name} port {port} open on {host} (SCADA-to-field-device protocol)",
                severity="high", confidence="certain",
                affected_asset=f"{host}:{port}",
                evidence=f"Real TCP connection established to {host}:{port}.",
                remediation=f"Restrict {name} to the OT network; use secure-authentication "
                            f"extensions where the protocol supports them (e.g. Secure DNP3).",
                tool="ot_ics.scada_security",
                references=["IEC-62443-3-3"],
            ))

    if not findings:
        return tool_result(
            "ot_ics.scada_security", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No exposed HMI web interfaces or SCADA protocol ports found on {host}",
            metadata={"hmi_web": hmi_results, "protocols": protocol_results},
        )

    return tool_result(
        "ot_ics.scada_security", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"SCADA/HMI-layer review of {host} found {len(findings)} finding(s)",
        metadata={"hmi_web": hmi_results, "protocols": protocol_results},
    )


tool_registry.register("ot_ics.scada_security", run, metadata={
    "name": "ot_ics.scada_security",
    "domain": "ot_ics",
    "status": "completed",
    "description": "Real SCADA/HMI-layer checks: HTTP probe of HMI web interfaces for missing auth, plus DNP3/IEC-104 port reachability",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "Per-probe timeout in seconds (default: 3.0)",
    },
})
