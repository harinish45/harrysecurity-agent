from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class PatternSelectorAgent(BaseAgent):
    name = "pattern_selector_agent"
    description = "orchestrator agent for pattern selection — selects the best agent coordination pattern"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        task_lower = task.lower()
        complexity_score = 0
        reasons = []

        if any(w in task_lower for w in ["complex", "multi", "comprehensive", "full", "deep"]):
            complexity_score += 3
            reasons.append("Task contains multi-phase/complex keywords")

        if any(w in task_lower for w in ["fast", "quick", "rapid", "simple"]):
            complexity_score -= 2
            reasons.append("Task indicates speed/simplicity priority")

        if any(w in task_lower for w in ["validate", "review", "audit", "check"]):
            complexity_score += 1
            reasons.append("Validation/review tasks require structured patterns")

        if any(w in task_lower for w in ["parallel", "concurrent", "simultaneous"]):
            complexity_score += 2
            reasons.append("Parallel execution keywords detected")

        if any(w in task_lower for w in ["sequential", "step", "ordered", "chain"]):
            complexity_score -= 1
            reasons.append("Sequential execution keywords detected")

        if complexity_score >= 3:
            pattern = "hierarchical"
            reasoning = "High complexity suggests hierarchical coordination with a commander and specialist sub-agents"
        elif complexity_score >= 1:
            pattern = "hybrid"
            reasoning = "Moderate complexity benefits from hybrid pattern combining swarm and chain approaches"
        elif any(w in task_lower for w in ["compare", "vote", "best", "auction"]):
            pattern = "auction"
            reasoning = "Task implies competitive selection among multiple approaches"
        elif any(w in task_lower for w in ["iterate", "refine", "recursive"]):
            pattern = "recursive"
            reasoning = "Task implies iterative refinement requiring recursive pattern"
        elif any(w in task_lower for w in ["parallel", "concurrent"]):
            pattern = "swarm"
            reasoning = "Parallel keywords suggest swarm pattern for concurrent execution"
        else:
            pattern = "chain_of_thought"
            reasoning = "Default sequential reasoning pattern for standard tasks"

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Selected coordination pattern: {pattern} for task complexity score {complexity_score}",
            metadata={
                "pattern": pattern,
                "complexity_score": complexity_score,
                "reasoning": reasoning,
                "reasons": reasons,
                "alternatives_considered": ["swarm", "chain_of_thought", "hierarchical", "hybrid", "auction", "recursive"],
            },
        )
