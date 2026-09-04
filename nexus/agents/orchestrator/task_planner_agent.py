from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class TaskPlannerAgent(BaseAgent):
    name = "task_planner_agent"
    description = "orchestrator agent for task planning — breaks missions into executable tasks with dependencies"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        for tool_name in ("reconnaissance.asset_discovery", "reconnaissance.dns_recon", "reconnaissance.whois_lookup"):
            try:
                result = tool_registry.run(tool_name, target=target)
                tools_used.append(tool_name)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        scope = {
            "target": target,
            "assets_discovered": len(findings),
            "recon_coverage": tools_used,
        }

        tasks = [
            {"id": "T1", "title": "Initial reconnaissance", "agent": "recon_agent", "depends_on": [], "priority": "high"},
            {"id": "T2", "title": "DNS and WHOIS enumeration", "agent": "recon_agent", "depends_on": ["T1"], "priority": "high"},
            {"id": "T3", "title": "Port scanning and service detection", "agent": "network_agent", "depends_on": ["T1"], "priority": "high"},
            {"id": "T4", "title": "Vulnerability scanning", "agent": "vuln_analyst_agent", "depends_on": ["T2", "T3"], "priority": "critical"},
            {"id": "T5", "title": "Exploit verification", "agent": "exploitation_agent", "depends_on": ["T4"], "priority": "medium"},
            {"id": "T6", "title": "Reporting and documentation", "agent": "reporter_agent", "depends_on": ["T4", "T5"], "priority": "high"},
        ]

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Task plan created for {target}: {len(tasks)} tasks across 3 phases, {len(tools_used)} scope tools used",
            metadata={
                "scope": scope,
                "tasks": tasks,
                "total_tasks": len(tasks),
                "tools_used": tools_used,
                "phases": {
                    "reconnaissance": ["T1", "T2"],
                    "assessment": ["T3", "T4"],
                    "exploitation_and_reporting": ["T5", "T6"],
                },
            },
        )
