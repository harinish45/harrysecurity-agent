from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class WirelessAgent(BaseAgent):
    name = "wireless_agent"
    description = "offensive agent for wireless — WiFi audit, Bluetooth, BLE, handshake capture, deauth, evil twin, and WPA/WPS testing"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            tool = tool_registry.get("wireless.wifi_audit")
            result = tool(target=target)
            tools_used.append("wireless.wifi_audit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"WiFi audit error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.bluetooth")
            result = tool(target=target)
            tools_used.append("wireless.bluetooth")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Bluetooth testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.ble")
            result = tool(target=target)
            tools_used.append("wireless.ble")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"BLE testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.handshake_capture")
            result = tool(target=target)
            tools_used.append("wireless.handshake_capture")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Handshake capture error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.deauth_test")
            result = tool(target=target)
            tools_used.append("wireless.deauth_test")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Deauth test error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.rogue_ap")
            result = tool(target=target)
            tools_used.append("wireless.rogue_ap")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Rogue AP error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.evil_twin")
            result = tool(target=target)
            tools_used.append("wireless.evil_twin")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Evil twin error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.wpa_test")
            result = tool(target=target)
            tools_used.append("wireless.wpa_test")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"WPA test error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("wireless.wps_attack")
            result = tool(target=target)
            tools_used.append("wireless.wps_attack")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"WPS attack error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Wireless security testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )