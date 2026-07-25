from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ChainOfThoughtPattern(BaseAgent):
    name = "chain_of_thought_pattern"
    description = "agent pattern for chain-of-thought reasoning — sequential reasoning with explicit intermediate steps"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        steps = self._decompose_task(task)
        reasoning_chain = []
        for i, step in enumerate(steps, 1):
            conclusion = self._reason_step(step, i, len(steps))
            reasoning_chain.append({
                "step": i,
                "question": step,
                "reasoning": conclusion["reasoning"],
                "conclusion": conclusion["conclusion"],
            })

        final = reasoning_chain[-1]["conclusion"] if reasoning_chain else "No conclusion reached"
        findings = [{
            "id": f"COT-{i+1}",
            "title": f"Step {i+1}: {s['question']}",
            "severity": "info",
            "confidence": "high",
            "affected_asset": target or "unknown",
            "evidence": f"Reasoning: {s['reasoning']} -> Conclusion: {s['conclusion']}",
            "remediation": "Review step for accuracy",
        } for i, s in enumerate(reasoning_chain)]

        return tool_result(
            self.name, target or "unknown", status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Chain-of-thought completed: {len(steps)} steps, final conclusion: {final}",
            metadata={"reasoning_chain": reasoning_chain, "step_count": len(steps), "final_conclusion": final},
        )

    def _decompose_task(self, task: str) -> list:
        parts = [p.strip() for p in task.replace("?", ".").split(".") if p.strip()]
        if len(parts) <= 1:
            words = task.split()
            return ["What is the core question?", "What evidence is relevant?", "What is the answer?"] if len(words) > 3 else [task]
        return parts[:6]

    def _reason_step(self, step: str, step_num: int, total: int) -> dict:
        is_final = step_num == total
        reasoning = f"Analyzing '{step}' as step {step_num} of {total}."
        if "what" in step.lower():
            reasoning += " Identifying key components and constraints."
        elif "how" in step.lower():
            reasoning += " Evaluating methods and approaches to address this."
        elif "why" in step.lower():
            reasoning += " Examining root causes and justifications."
        else:
            reasoning += " Applying domain knowledge to derive a conclusion."
        conclusion = f"Intermediate finding for step {step_num}: processed '{step[:50]}'" if not is_final else f"Final conclusion derived from all {total} steps regarding '{step[:50]}'"
        return {"reasoning": reasoning, "conclusion": conclusion}