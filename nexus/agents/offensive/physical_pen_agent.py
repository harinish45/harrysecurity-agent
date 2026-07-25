from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class PhysicalPenAgent(BaseAgent):
    name = "physical_pen_agent"
    description = "offensive agent for physical penetration — RFID, USB attacks, rubber ducky, fault injection, and side-channel analysis"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            tool = tool_registry.get("hardware.rfid_testing")
            result = tool(target=target)
            tools_used.append("hardware.rfid_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"RFID testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("hardware.usb_attacks")
            result = tool(target=target)
            tools_used.append("hardware.usb_attacks")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"USB attack error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("hardware.rubber_ducky_testing")
            result = tool(target=target)
            tools_used.append("hardware.rubber_ducky_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Rubber ducky testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("hardware.fault_injection")
            result = tool(target=target)
            tools_used.append("hardware.fault_injection")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Fault injection error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("hardware.secure_boot_testing")
            result = tool(target=target)
            tools_used.append("hardware.secure_boot_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Secure boot testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("hardware.side_channel_analysis")
            result = tool(target=target)
            tools_used.append("hardware.side_channel_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Side-channel analysis error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Physical penetration testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )