"""Reports (and can hard-stop against) a mission's estimated LLM spend via
``nexus.foundation.guardrails.BudgetGuard``.

Not wired into every one of the ~60 agents' LLM calls in this pass — that
would touch dozens of files for marginal gain right now. It's wired at the
two highest-volume call sites (`OrchestrationEngine._plan_mission`,
`debate_consensus_agent`) plus this reporting agent, which any mode/CLI
command can call to see the running total and decide whether to continue.
"""
from __future__ import annotations

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.guardrails.budget_guard import BudgetGuard
from nexus.foundation.schema import STATUS_COMPLETED, tool_result


class BudgetGovernorAgent(BaseAgent):
    name = "budget_governor_agent"
    description = "orchestrator agent that reports a mission's estimated LLM token/cost spend"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        mission_id = kwargs.get("mission_id", "mission")
        report = BudgetGuard.report(mission_id)

        max_tokens = kwargs.get("max_tokens")
        max_usd = kwargs.get("max_usd")
        over_budget = (
            (max_tokens is not None and report["estimated_tokens"] > max_tokens)
            or (max_usd is not None and report["estimated_usd"] > max_usd)
        )

        return tool_result(
            self.name, target or mission_id,
            status=STATUS_COMPLETED,
            findings=[],
            summary=(
                f"Mission {mission_id}: ~{report['estimated_tokens']} estimated tokens, "
                f"~${report['estimated_usd']:.4f} estimated spend across {report['calls']} LLM call(s)"
            ),
            metadata={**report, "over_budget": over_budget},
        )
