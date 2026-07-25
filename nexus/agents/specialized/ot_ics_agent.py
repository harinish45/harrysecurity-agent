from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class OtIcsAgent(BaseAgent):
    name = "ot_ics_agent"
    description = "specialized agent for OT/ICS — Modbus, DNP3, PLC testing, SCADA security, and industrial protocol reviews"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            tool = tool_registry.get("ot_ics.modbus_analysis")
            result = tool(target=target)
            tools_used.append("ot_ics.modbus_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Modbus analysis error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("ot_ics.dnp3_testing")
            result = tool(target=target)
            tools_used.append("ot_ics.dnp3_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"DNP3 testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("ot_ics.plc_testing")
            result = tool(target=target)
            tools_used.append("ot_ics.plc_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"PLC testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("ot_ics.scada_security")
            result = tool(target=target)
            tools_used.append("ot_ics.scada_security")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SCADA security error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("ot_ics.industrial_protocol_reviews")
            result = tool(target=target)
            tools_used.append("ot_ics.industrial_protocol_reviews")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Industrial protocol review error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"OT/ICS security testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )