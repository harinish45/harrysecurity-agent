from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class SocialEngAgent(BaseAgent):
    name = "social_eng_agent"
    description = "offensive agent for social engineering — OSINT, email harvesting, GitHub recon, and DNS recon"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            tool = tool_registry.get("reconnaissance.social_osint")
            result = tool(target=target)
            tools_used.append("reconnaissance.social_osint")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Social OSINT error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("reconnaissance.email_harvest")
            result = tool(target=target)
            tools_used.append("reconnaissance.email_harvest")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Email harvesting error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("reconnaissance.github_recon")
            result = tool(target=target)
            tools_used.append("reconnaissance.github_recon")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"GitHub recon error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("reconnaissance.dns_recon")
            result = tool(target=target)
            tools_used.append("reconnaissance.dns_recon")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"DNS recon error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("reconnaissance.whois_lookup")
            result = tool(target=target)
            tools_used.append("reconnaissance.whois_lookup")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"WHOIS lookup error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Social engineering reconnaissance completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )