#!/usr/bin/env python3
"""
NEXUS-STRIKE — automation.python_scripting
Domain: automation
Trivially real self-check: report the real interpreter version this
platform is running under, plus a real importability check of
security-relevant modules (requests, scapy, ldap3). This is a self-check of
NEXUS-STRIKE's execution environment, not an assessment of `target`.

Previously this ignored `target` entirely (beyond a bare DNS resolve + HTTP
GET on "/", byte-for-byte identical to 19 other stub tools; a still-earlier
version unsafely read `target` as a local file path) — caught during this
session's audit.
"""
from __future__ import annotations

import importlib.util
import platform
import sys
from typing import Any

from nexus.foundation.schema import Finding, STATUS_COMPLETED, tool_result
from nexus.tools.registry import tool_registry

_SECURITY_MODULES = ("requests", "scapy", "ldap3")


def run(target: str, **kwargs: Any) -> dict:
    """Self-check: real interpreter version and real importability of security-relevant modules."""
    tool_name = "automation.python_scripting"
    node = platform.node()
    version = platform.python_version()

    available: dict[str, bool] = {m: importlib.util.find_spec(m) is not None for m in _SECURITY_MODULES}

    findings = [Finding(
        title=f"Python interpreter: {version}",
        severity="info", confidence="certain",
        affected_asset=node,
        evidence=f"sys.version={sys.version.split()[0]}, implementation={platform.python_implementation()}",
        remediation="No action needed — informational platform-capability check.",
        tool=tool_name,
    )]
    for module_name, ok in available.items():
        findings.append(Finding(
            title=f"Security-relevant module '{module_name}' {'importable' if ok else 'not importable'}",
            severity="info" if ok else "low", confidence="certain",
            affected_asset=node,
            evidence=f"importlib.util.find_spec({module_name!r}) -> {'found' if ok else 'not found'}",
            remediation="No action needed." if ok else f"Install {module_name} if python-scripting playbooks depend on it.",
            tool=tool_name,
        ))

    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real local capability check: Python {version} on {node} with modules {available}. "
                f"This is a self-check of the execution environment, not an assessment of {target}.",
        metadata={"python_version": version, "modules_available": available},
    )


tool_registry.register("automation.python_scripting", run, metadata={
    "name": "automation.python_scripting",
    "domain": "automation",
    "status": "completed",
    "description": "Real self-check of the Python interpreter version and importability of "
                    "security-relevant modules (requests, scapy, ldap3)",
    "parameters": {
        "target": "Unused for scanning purposes — this is a self-check of the local platform",
    },
})
