from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ThreatHuntAgent(BaseAgent):
    name = "threat_hunt_agent"
    description = "defensive agent for threat hunting — threat hunts, UEBA, and threat feed correlation"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Threat hunting (blue team)
        try:
            hunt_blue = tool_registry.get("blue_team.threat_hunting_blue")
            result = hunt_blue(target=target)
            tools_used.append("blue_team.threat_hunting_blue")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Threat hunting error: {e}", "severity": "low", "confidence": "medium"})

        # Threat feeds
        try:
            feeds = tool_registry.get("threat_intel.threat_feeds")
            result = feeds(target=target)
            tools_used.append("threat_intel.threat_feeds")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Threat feeds error: {e}", "severity": "low", "confidence": "medium"})

        # UEBA
        try:
            ueba = tool_registry.get("soc.ueba")
            result = ueba(target=target)
            tools_used.append("soc.ueba")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"UEBA error: {e}", "severity": "low", "confidence": "medium"})

        # Threat hunting (IR)
        try:
            hunt_ir = tool_registry.get("incident_response.threat_hunting")
            result = hunt_ir(target=target)
            tools_used.append("incident_response.threat_hunting")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"IR threat hunting error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Threat hunting completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
