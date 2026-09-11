from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ReverseEngAgent(BaseAgent):
    name = "reverse_eng_agent"
    description = "analysis agent for reverse engineering — assembly analysis, binary patching, and firmware RE"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Assembly analysis
        try:
            result = tool_registry.run("reverse_engineering.assembly_analysis", target=target)
            tools_used.append("reverse_engineering.assembly_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Assembly analysis error: {e}", "severity": "low", "confidence": "medium"})

        # Binary patching
        try:
            result = tool_registry.run("reverse_engineering.binary_patching", target=target)
            tools_used.append("reverse_engineering.binary_patching")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Binary patching error: {e}", "severity": "low", "confidence": "medium"})

        # Firmware reverse engineering
        try:
            result = tool_registry.run("reverse_engineering.firmware_reverse_engineering", target=target)
            tools_used.append("reverse_engineering.firmware_reverse_engineering")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Firmware RE error: {e}", "severity": "low", "confidence": "medium"})

        # Ghidra analysis
        try:
            result = tool_registry.run("reverse_engineering.ghidra_analysis", target=target)
            tools_used.append("reverse_engineering.ghidra_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Ghidra analysis error: {e}", "severity": "low", "confidence": "medium"})

        # IDA analysis
        try:
            result = tool_registry.run("reverse_engineering.ida_analysis", target=target)
            tools_used.append("reverse_engineering.ida_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"IDA analysis error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Reverse engineering analysis completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
