from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class DeceptionAgent(BaseAgent):
    name = "deception_agent"
    description = "defensive agent for deception — hardening, firewall management, and policy reviews"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Hardening
        try:
            result = tool_registry.run("blue_team.hardening", target=target)
            tools_used.append("blue_team.hardening")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Hardening error: {e}", "severity": "low", "confidence": "medium"})

        # Firewall management
        try:
            result = tool_registry.run("blue_team.firewall_management", target=target)
            tools_used.append("blue_team.firewall_management")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Firewall management error: {e}", "severity": "low", "confidence": "medium"})

        # Endpoint protection
        try:
            result = tool_registry.run("blue_team.endpoint_protection", target=target)
            tools_used.append("blue_team.endpoint_protection")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Endpoint protection error: {e}", "severity": "low", "confidence": "medium"})

        # Policy reviews
        try:
            result = tool_registry.run("compliance.policy_reviews", target=target)
            tools_used.append("compliance.policy_reviews")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Policy reviews error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Deception assessment completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
