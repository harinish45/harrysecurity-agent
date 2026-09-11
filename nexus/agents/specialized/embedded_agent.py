from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class EmbeddedAgent(BaseAgent):
    name = "embedded_agent"
    description = "specialized agent for embedded systems — embedded Linux, firmware extraction, JTAG, UART, and secure boot testing"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("iot.embedded_linux", target=target)
            tools_used.append("iot.embedded_linux")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Embedded Linux error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("iot.firmware_extraction", target=target)
            tools_used.append("iot.firmware_extraction")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Firmware extraction error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("iot.jtag_analysis", target=target)
            tools_used.append("iot.jtag_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"JTAG analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("iot.uart_analysis", target=target)
            tools_used.append("iot.uart_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"UART analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("hardware.secure_boot_testing", target=target)
            tools_used.append("hardware.secure_boot_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Secure boot testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("hardware.fault_injection", target=target)
            tools_used.append("hardware.fault_injection")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Fault injection error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Embedded systems testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )