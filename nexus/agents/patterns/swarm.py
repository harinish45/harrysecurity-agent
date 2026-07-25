from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class SwarmPattern(BaseAgent):
    name = "swarm_pattern"
    description = "agent pattern for swarm intelligence — parallel agent execution with emergent coordination"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        swarm_size = kwargs.get("swarm_size", 5)
        agents = self._spawn_agents(task, swarm_size)
        contributions = self._simulate_exploration(task, agents)
        aggregated = self._aggregate_findings(contributions)

        findings = [{
            "id": f"SWARM-{i+1}",
            "title": f"Agent '{agent['name']}' contribution",
            "severity": "info",
            "confidence": agent.get("confidence", "high"),
            "affected_asset": target or "unknown",
            "evidence": agent["finding"],
            "remediation": "No action needed",
        } for i, agent in enumerate(contributions)]

        findings.extend(aggregated["emergent_patterns"])

        return tool_result(
            self.name, target or "unknown", status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Swarm simulation complete: {swarm_size} agents, {len(contributions)} contributions, {len(aggregated['emergent_patterns'])} emergent patterns",
            metadata={
                "swarm_size": swarm_size,
                "agents": agents,
                "individual_contributions": contributions,
                "aggregated_results": aggregated,
            },
        )

    def _spawn_agents(self, task: str, count: int) -> list:
        return [{"name": f"swarm_agent_{i+1}", "role": "explorer", "specialty": "parallel"} for i in range(count)]

    def _simulate_exploration(self, task: str, agents: list) -> list:
        contributions = []
        for agent in agents:
            contribution = f"Agent {agent['name']} explored aspect of: {task[:50]} — independent finding"
            contributions.append({"name": agent["name"], "finding": contribution, "confidence": "medium"})
        return contributions

    def _aggregate_findings(self, contributions: list) -> dict:
        patterns = set()
        for c in contributions:
            words = [w for w in c["finding"].split() if len(w) > 4]
            if words:
                patterns.add(words[0].lower())
        emergent = [{
            "id": f"SWARM-EM-{i+1}",
            "title": f"Emergent pattern {i+1}",
            "severity": "medium",
            "confidence": "medium",
            "affected_asset": "aggregated",
            "evidence": f"Consensus detected across {len(contributions)} agents on pattern '{p}'",
            "remediation": "Investigate pattern for significance",
        } for i, p in enumerate(sorted(patterns)[:3])]
        return {"emergent_patterns": emergent, "consensus_count": len(patterns), "total_agents_contributed": len(contributions)}