#!/usr/bin/env python3
"""
NEXUS-STRIKE — wireless.wpa_handshake_capture
Domain: wireless
Real WPA handshake capture analysis: checks for monitor mode and scapy availability.
"""
from __future__ import annotations
import os
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result
from nexus.tools.registry import tool_registry

def run(target: str, **kwargs: Any) -> dict:
    """Analyze environment for WPA handshake capture capabilities (monitor mode + scapy)."""
    findings = []
    capabilities = {"scapy_installed": False, "monitor_mode": False}
    
    try:
        # Check for scapy
        try:
            import scapy.all
            capabilities["scapy_installed"] = True
        except ImportError:
            findings.append(Finding(
                title="Scapy Not Installed",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence="The 'scapy' Python module is not installed, preventing packet crafting and capture.",
                remediation="pip install scapy (requires root/administrator privileges for raw socket access).",
                tool="wireless.wpa_handshake_capture",
                references=[]
            ))
            return tool_result(
                "wireless.wpa_handshake_capture", target,
                status=STATUS_UNAVAILABLE,
                findings=findings,
                summary="WPA handshake capture unavailable: scapy not installed.",
                metadata=capabilities
            )
        
        # Check for monitor mode interfaces (e.g., wlan0mon)
        interfaces = os.listdir("/sys/class/net/") if os.path.exists("/sys/class/net/") else []
        monitor_interfaces = [iface for iface in interfaces if "mon" in iface]
        
        if monitor_interfaces:
            capabilities["monitor_mode"] = True
            findings.append(Finding(
                title="Monitor Mode Interface Detected",
                severity="medium",
                confidence="high",
                affected_asset=", ".join(monitor_interfaces),
                evidence=f"Monitor mode interfaces found: {', '.join(monitor_interfaces)}. The system is capable of capturing 802.11 management frames, including WPA 4-way handshakes.",
                remediation="Ensure wireless auditing is authorized. Restrict physical access to auditing hardware.",
                tool="wireless.wpa_handshake_capture",
                references=["MITRE ATT&CK T1557.001"]
            ))
        else:
            findings.append(Finding(
                title="No Monitor Mode Interface Detected",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence="No wireless interfaces in monitor mode (e.g., wlan0mon) were found. Handshake capture is not currently possible.",
                remediation="Use 'airmon-ng start wlan0' or equivalent to enable monitor mode on a compatible wireless adapter.",
                tool="wireless.wpa_handshake_capture",
                references=[]
            ))
            
        summary = f"WPA handshake capture analysis completed. Scapy: {capabilities['scapy_installed']}, Monitor mode: {capabilities['monitor_mode']}."
        status = STATUS_COMPLETED if capabilities["monitor_mode"] else STATUS_NO_FINDINGS
        
    except Exception as e:
        return tool_result("wireless.wpa_handshake_capture", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "wireless.wpa_handshake_capture", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata=capabilities
    )

tool_registry.register("wireless.wpa_handshake_capture", run, metadata={
    "name": "wireless.wpa_handshake_capture",
    "domain": "wireless",
    "status": "completed",
    "description": "Checks for monitor mode and scapy availability for WPA handshake capture",
    "parameters": {"target": "Target wireless interface or hostname"},
})