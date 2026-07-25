from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class BlueTeamAgent(BaseAgent):
    name = "blue_team_agent"
    description = "defensive agent for blue team operations — EDR analysis, log review, and endpoint protection"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Endpoint protection
        try:
            ep = tool_registry.get("blue_team.endpoint_protection")
            result = ep(target=target)
            tools_used.append("blue_team.endpoint_protection")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Endpoint protection error: {e}", "severity": "low", "confidence": "medium"})

        # EDR analysis
        try:
            edr = tool_registry.get("blue_team.edr_analysis")
            result = edr(target=target)
            tools_used.append("blue_team.edr_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"EDR analysis error: {e}", "severity": "low", "confidence": "medium"})

        # Log review
        try:
            log = tool_registry.get("blue_team.log_review")
            result = log(target=target)
            tools_used.append("blue_team.log_review")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Log review error: {e}", "severity": "low", "confidence": "medium"})

        # Threat hunting (blue team)
        try:
            hunt = tool_registry.get("blue_team.threat_hunting_blue")
            result = hunt(target=target)
            tools_used.append("blue_team.threat_hunting_blue")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Threat hunting error: {e}", "severity": "low", "confidence": "medium"})

        # SIEM monitoring
        try:
            siem = tool_registry.get("soc.siem_monitoring")
            result = siem(target=target)
            tools_used.append("soc.siem_monitoring")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SIEM monitoring error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Blue team operations completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
