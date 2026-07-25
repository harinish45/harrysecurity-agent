from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class AuctionPattern(BaseAgent):
    name = "auction_pattern"
    description = "agent pattern for auction-based coordination — agents bid on tasks based on capability and cost"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        requirements = self._parse_requirements(task)
        bids = self._generate_bids(requirements)
        winner = self._select_winner(bids)

        if not winner:
            return tool_result(
                self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                findings=[], summary="No suitable agent bid on the task",
            )

        findings = [{
            "id": f"AUCTION-{i+1}",
            "title": f"Bid from {b['agent']}",
            "severity": "info",
            "confidence": "high",
            "affected_asset": target or "unknown",
            "evidence": f"Capability score: {b['capability']}, Cost: {b['cost']}",
            "remediation": "No action needed",
        } for i, b in enumerate(bids)]

        return tool_result(
            self.name, target or "unknown", status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Auction complete: winner is {winner['agent']} with bid {winner['cost']}",
            metadata={
                "requirements": requirements,
                "bids": bids,
                "winner": winner,
                "rationale": f"Selected {winner['agent']} for best capability-to-cost ratio of {winner['ratio']:.2f}",
            },
        )

    def _parse_requirements(self, task: str) -> dict:
        keywords = {"scan": "reconnaissance", "exploit": "offensive", "analyze": "analysis", "report": "support", "monitor": "defensive"}
        reqs = {"complexity": "medium", "capabilities_needed": [], "budget": 100}
        for word, domain in keywords.items():
            if word in task.lower():
                reqs["capabilities_needed"].append(domain)
        if len(reqs["capabilities_needed"]) > 2:
            reqs["complexity"] = "high"
        return reqs

    def _generate_bids(self, requirements: dict) -> list:
        agents = [
            {"agent": "recon_agent", "capability": 0.9, "cost": 80},
            {"agent": "network_agent", "capability": 0.85, "cost": 70},
            {"agent": "vuln_analyst_agent", "capability": 0.95, "cost": 90},
            {"agent": "reporter_agent", "capability": 0.7, "cost": 40},
            {"agent": "redteam_agent", "capability": 0.88, "cost": 85},
        ]
        for bid in agents:
            bid["ratio"] = round(bid["capability"] / max(bid["cost"], 1), 4)
        return sorted(agents, key=lambda b: b["ratio"], reverse=True)[:5]

    def _select_winner(self, bids: list) -> dict:
        if not bids:
            return {}
        return bids[0]