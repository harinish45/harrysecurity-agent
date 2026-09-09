from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class AgentRouterAgent(BaseAgent):
    name = "agent_router_agent"
    description = "orchestrator agent for routing — analyzes tasks and routes to appropriate specialist agents"

    # Domain names here are real nexus/tools/<domain>/ directories (verified
    # against the actual tool tree, not guessed) — "cloud_security"/
    # "offensive" in the old keyword table weren't real domains at all, so
    # every task routed to them silently fell through to nothing.
    _KEYWORD_DOMAINS = {
        "dns": "reconnaissance", "subdomain": "reconnaissance", "port": "network",
        "vulnerability": "vuln_assessment", "malware": "malware", "phishing": "threat_intel",
        "compliance": "compliance", "password": "red_team", "web": "appsec",
        "cloud": "cloud", "forensics": "forensics", "reverse": "reverse_engineering",
    }
    # One real, registered representative tool per domain this agent can
    # route to — this is what makes the routing decision and the actual
    # work performed the same decision. Previously `run()` always executed
    # the same 3 hardcoded reconnaissance.* tools regardless of which
    # domain(s) `recommended_domains` named.
    _DOMAIN_TOOLS = {
        "reconnaissance": "reconnaissance.dns_recon",
        "network": "network.port_scan",
        "vuln_assessment": "vuln_assessment.network_vuln_scanning",
        "malware": "malware.hash_analysis",
        "threat_intel": "threat_intel.threat_feeds",
        "compliance": "compliance.security_audits",
        "red_team": "red_team.initial_access_simulation",
        "appsec": "appsec.secret_scanning",
        "cloud": "cloud.aws_review",
        "forensics": "forensics.log_analysis",
        "reverse_engineering": "reverse_engineering.ghidra_analysis",
    }

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        findings = []
        tools_used = []
        task_lower = task.lower()

        recommended_domains = set()
        for kw, domain in self._KEYWORD_DOMAINS.items():
            if kw in task_lower:
                recommended_domains.add(domain)

        if not recommended_domains:
            recommended_domains = {"reconnaissance", "vuln_assessment"}

        routed_tools: dict[str, str] = {}
        for domain in sorted(recommended_domains):
            tool_name = self._DOMAIN_TOOLS.get(domain)
            if not tool_name:
                continue
            routed_tools[domain] = tool_name
            try:
                result = tool_registry.run(tool_name, target=target or "scope-unknown")
                tools_used.append(tool_name)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        recommended_agents = sorted(recommended_domains)
        summary = (
            f"Task routed to domains: {', '.join(recommended_agents)} -> "
            f"{', '.join(f'{d}:{t}' for d, t in routed_tools.items())}. "
            f"{len(tools_used)} tool(s) run, {len(findings)} finding(s)."
        )

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=findings,
            summary=summary,
            metadata={
                "recommended_domains": recommended_agents,
                "recommended_agents": recommended_agents,
                "routed_tools": routed_tools,
                "tools_used": tools_used,
                "task_keywords": [kw for kw in self._KEYWORD_DOMAINS if kw in task_lower],
            },
        )
