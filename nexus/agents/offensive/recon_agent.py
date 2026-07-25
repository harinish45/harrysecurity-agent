from nexus.agents.base_agent import BaseAgent, AgentContext
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ReconAgent(BaseAgent):
    name = "recon_agent"
    description = "offensive agent for reconnaissance — subdomain enum, DNS recon, tech fingerprint"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Subdomain enumeration
        try:
            sub_enum = tool_registry.get("reconnaissance.subdomain_enum")
            result = sub_enum(target=target)
            tools_used.append("reconnaissance.subdomain_enum")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Subdomain enum error: {e}", "severity": "low", "confidence": "medium"})

        # DNS reconnaissance
        try:
            dns_recon = tool_registry.get("reconnaissance.dns_recon")
            result = dns_recon(target=target)
            tools_used.append("reconnaissance.dns_recon")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"DNS recon error: {e}", "severity": "low", "confidence": "medium"})

        # Technology fingerprinting
        try:
            tech_fp = tool_registry.get("reconnaissance.tech_fingerprint")
            result = tech_fp(target=target)
            tools_used.append("reconnaissance.tech_fingerprint")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Tech fingerprint error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Reconnaissance completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
