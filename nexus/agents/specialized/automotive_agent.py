from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class AutomotiveAgent(BaseAgent):
    name = "automotive_agent"
    description = "specialized agent for automotive — CAN bus analysis, ECU reverse engineering, and vehicle network testing"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            tool = tool_registry.get("automotive.can_bus_analysis")
            result = tool(target=target)
            tools_used.append("automotive.can_bus_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"CAN bus analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("automotive.ecu_reverse_engineering")
            result = tool(target=target)
            tools_used.append("automotive.ecu_reverse_engineering")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"ECU reverse engineering error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("automotive.vehicle_network_testing")
            result = tool(target=target)
            tools_used.append("automotive.vehicle_network_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Vehicle network testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("automotive.automotive_firmware_analysis")
            result = tool(target=target)
            tools_used.append("automotive.automotive_firmware_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Automotive firmware analysis error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Automotive security testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )