from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class MissionCommanderAgent(BaseAgent):
    name = "mission_commander_agent"
    description = "orchestrator agent for mission command — plans overall mission strategy and coordinates phases"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        for tool_name in ("reconnaissance.asset_discovery", "reconnaissance.subdomain_enum", "reconnaissance.dns_recon"):
            try:
                result = tool_registry.run(tool_name, target=target)
                tools_used.append(tool_name)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        phases = [
            {"phase": 1, "name": "Reconnaissance", "agents": ["network_agent", "recon_agent", "searcher_agent"], "tools": tools_used[:3]},
            {"phase": 2, "name": "Vulnerability Assessment", "agents": ["vuln_analyst_agent", "webapp_agent"], "tools": ["vuln_assessment.scan", "appsec.dependency_analysis"]},
            {"phase": 3, "name": "Exploitation", "agents": ["exploitation_agent", "post_exploitation_agent"], "tools": ["offensive.exploit", "offensive.privesc"]},
            {"phase": 4, "name": "Reporting", "agents": ["reporter_agent", "doc_writer_agent"], "tools": ["reporting.generate", "compliance.policy_reviews"]},
        ]

        for p in phases:
            p["estimated_tools"] = len(p["tools"])

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Mission planned for {target}: {len(phases)} phases, {len(tools_used)} scope tools used",
            metadata={
                "phases": phases,
                "total_phases": len(phases),
                "tools_used": tools_used,
                "estimated_total_tools": sum(p["estimated_tools"] for p in phases),
            },
        )
