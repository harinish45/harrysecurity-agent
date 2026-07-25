from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class IrAgent(BaseAgent):
    name = "ir_agent"
    description = "defensive agent for incident response — alert triage, investigation, eradication, and recovery"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Alert triage
        try:
            triage = tool_registry.get("incident_response.alert_triage")
            result = triage(target=target)
            tools_used.append("incident_response.alert_triage")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Alert triage error: {e}", "severity": "low", "confidence": "medium"})

        # Incident investigation
        try:
            investigation = tool_registry.get("incident_response.incident_investigation")
            result = investigation(target=target)
            tools_used.append("incident_response.incident_investigation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Incident investigation error: {e}", "severity": "low", "confidence": "medium"})

        # Eradication
        try:
            eradication = tool_registry.get("incident_response.eradication")
            result = eradication(target=target)
            tools_used.append("incident_response.eradication")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Eradication error: {e}", "severity": "low", "confidence": "medium"})

        # Malware containment
        try:
            containment = tool_registry.get("incident_response.malware_containment")
            result = containment(target=target)
            tools_used.append("incident_response.malware_containment")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Malware containment error: {e}", "severity": "low", "confidence": "medium"})

        # Recovery
        try:
            recovery = tool_registry.get("incident_response.recovery")
            result = recovery(target=target)
            tools_used.append("incident_response.recovery")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Recovery error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Incident response completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
