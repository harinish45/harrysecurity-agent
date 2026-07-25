#!/usr/bin/env python3
"""
NEXUS-STRIKE — iot tool: Smart Device Assessment
Domain: iot
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """iot tool: Smart Device Assessment"""
    findings = []
    try:
        import socket
        import urllib.request
        # Check if target is reachable
        try:
            ip = socket.gethostbyname(target)
            findings.append(f"Target {target} -> {ip}")
        except:
            findings.append(f"DNS resolution failed for {target}")
        # Check common IoT ports
        ports = [23, 80, 443, 554, 8080, 8081, 8443, 9000, 9090, 37777, 37778, 41993]
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((target, port), timeout=1):
                    open_ports.append(port)
            except:
                pass
        if open_ports:
            findings.append(f"Open IoT ports: {open_ports}")
        else:
            findings.append("No common IoT ports open")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "iot.smart_device_assessment", "domain": "iot", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("iot.smart_device_assessment", run, metadata={
    "name": "iot.smart_device_assessment",
    "domain": "iot",
    "status": "completed",
    "description": "iot tool: Smart Device Assessment",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
