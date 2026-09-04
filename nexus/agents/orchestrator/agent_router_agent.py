from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class AgentRouterAgent(BaseAgent):
    name = "agent_router_agent"
    description = "orchestrator agent for routing — analyzes tasks and routes to appropriate specialist agents"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        findings = []
        tools_used = []
        task_lower = task.lower()

        keyword_domains = {
            "dns": "reconnaissance", "subdomain": "reconnaissance", "port": "network",
            "vulnerability": "vuln_assessment", "malware": "malware", "phishing": "threat_intel",
            "compliance": "compliance", "password": "offensive", "web": "appsec",
            "cloud": "cloud_security", "forensics": "forensics", "reverse": "reverse_engineering",
        }
        recommended_domains = set()
        for kw, domain in keyword_domains.items():
            if kw in task_lower:
                recommended_domains.add(domain)

        if not recommended_domains:
            recommended_domains = {"reconnaissance", "vuln_assessment"}

        recon_tools = {
            "reconnaissance.subdomain_enum": "subdomain enumeration",
            "reconnaissance.dns_recon": "DNS reconnaissance",
            "reconnaissance.asset_discovery": "asset discovery",
        }

        for tool_name, purpose in recon_tools.items():
            try:
                result = tool_registry.run(tool_name, target=target or "scope-unknown")
                tools_used.append(tool_name)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{purpose} error: {e}", "severity": "low", "confidence": "medium"})

        recommended_agents = sorted(recommended_domains)
        summary = (
            f"Task routed to domains: {', '.join(recommended_agents)}. "
            f"Used {len(tools_used)} recon tools, {len(findings)} findings."
        )

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=findings,
            summary=summary,
            metadata={
                "recommended_domains": recommended_agents,
                "recommended_agents": recommended_agents,
                "tools_used": tools_used,
                "task_keywords": [kw for kw in keyword_domains if kw in task_lower],
            },
        )
