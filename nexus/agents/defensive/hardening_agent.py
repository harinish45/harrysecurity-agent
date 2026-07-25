from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class HardeningAgent(BaseAgent):
    name = "hardening_agent"
    description = "defensive agent for hardening — system hardening, firewall management, and endpoint protection"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Hardening
        try:
            harden = tool_registry.get("blue_team.hardening")
            result = harden(target=target)
            tools_used.append("blue_team.hardening")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Hardening error: {e}", "severity": "low", "confidence": "medium"})

        # Firewall management
        try:
            fw = tool_registry.get("blue_team.firewall_management")
            result = fw(target=target)
            tools_used.append("blue_team.firewall_management")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Firewall management error: {e}", "severity": "low", "confidence": "medium"})

        # Endpoint protection
        try:
            ep = tool_registry.get("blue_team.endpoint_protection")
            result = ep(target=target)
            tools_used.append("blue_team.endpoint_protection")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Endpoint protection error: {e}", "severity": "low", "confidence": "medium"})

        # Policy reviews
        try:
            policy = tool_registry.get("compliance.policy_reviews")
            result = policy(target=target)
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
            summary=f"Hardening assessment completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
