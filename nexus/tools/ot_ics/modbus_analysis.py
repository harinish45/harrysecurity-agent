#!/usr/bin/env python3
"""
NEXUS-STRIKE — ot_ics tool: Modbus Analysis
Domain: ot_ics
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """ot_ics tool: Modbus Analysis"""
    findings = []
    try:
        import socket
        # Check common ICS/SCADA ports
        ports = [502, 102, 1080, 2222, 2455, 5020, 5021, 5022, 5023, 5024, 5025, 504, 10000, 10001, 19410, 19411, 19412, 19413, 19414, 19415]
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((target, port), timeout=1):
                    open_ports.append(port)
            except:
                pass
        if open_ports:
            findings.append(f"Open ICS/SCADA ports: {open_ports}")
            ics_services = {502: "Modbus", 102: "S7", 504: "Modbus/TCP", 10000: "Siemens S7"}
            for p in open_ports:
                svc = ics_services.get(p, "Unknown ICS protocol")
                findings.append(f"Port {p}: {svc}")
        else:
            findings.append("No common ICS/SCADA ports open")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "ot_ics.modbus_analysis", "domain": "ot_ics", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("ot_ics.modbus_analysis", run, metadata={
    "name": "ot_ics.modbus_analysis",
    "domain": "ot_ics",
    "status": "completed",
    "description": "ot_ics tool: Modbus Analysis",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
