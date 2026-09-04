from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class OsintAnalystAgent(BaseAgent):
    name = "osint_analyst_agent"
    description = "analysis agent for OSINT — subdomain enum, DNS recon, social OSINT, and email harvesting"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Subdomain enumeration
        try:
            result = tool_registry.run("reconnaissance.subdomain_enum", target=target)
            tools_used.append("reconnaissance.subdomain_enum")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Subdomain enumeration error: {e}", "severity": "low", "confidence": "medium"})

        # DNS reconnaissance
        try:
            result = tool_registry.run("reconnaissance.dns_recon", target=target)
            tools_used.append("reconnaissance.dns_recon")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"DNS reconnaissance error: {e}", "severity": "low", "confidence": "medium"})

        # WHOIS lookup
        try:
            result = tool_registry.run("reconnaissance.whois_lookup", target=target)
            tools_used.append("reconnaissance.whois_lookup")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"WHOIS lookup error: {e}", "severity": "low", "confidence": "medium"})

        # GitHub reconnaissance
        try:
            result = tool_registry.run("reconnaissance.github_recon", target=target)
            tools_used.append("reconnaissance.github_recon")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"GitHub recon error: {e}", "severity": "low", "confidence": "medium"})

        # Social OSINT
        try:
            result = tool_registry.run("reconnaissance.social_osint", target=target)
            tools_used.append("reconnaissance.social_osint")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Social OSINT error: {e}", "severity": "low", "confidence": "medium"})

        # Email harvesting
        try:
            result = tool_registry.run("reconnaissance.email_harvest", target=target)
            tools_used.append("reconnaissance.email_harvest")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Email harvest error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"OSINT analysis completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
