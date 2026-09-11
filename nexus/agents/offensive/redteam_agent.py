from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class RedteamAgent(BaseAgent):
    name = "redteam_agent"
    description = "offensive agent for red teaming — initial access, lateral movement, persistence, credential access, and exfiltration"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("red_team.initial_access_simulation", target=target)
            tools_used.append("red_team.initial_access_simulation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Initial access simulation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("red_team.lateral_movement_simulation", target=target)
            tools_used.append("red_team.lateral_movement_simulation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Lateral movement simulation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("red_team.persistence_simulation", target=target)
            tools_used.append("red_team.persistence_simulation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Persistence simulation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("red_team.credential_access_simulation", target=target)
            tools_used.append("red_team.credential_access_simulation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Credential access simulation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("red_team.exfiltration_simulation", target=target)
            tools_used.append("red_team.exfiltration_simulation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Exfiltration simulation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("red_team.defense_evasion_simulation", target=target)
            tools_used.append("red_team.defense_evasion_simulation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Defense evasion simulation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("red_team.discovery_simulation", target=target)
            tools_used.append("red_team.discovery_simulation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Discovery simulation error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Red team simulation completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )