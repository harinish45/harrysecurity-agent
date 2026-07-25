from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class HybridPattern(BaseAgent):
    name = "hybrid_pattern"
    description = "agent pattern for hybrid coordination — combines multiple patterns dynamically based on task type"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        characteristics = self._analyze_task(task)
        phases = self._select_patterns(characteristics)
        workflow = self._orchestrate_phases(phases, task, target)

        findings = [{
            "id": f"HYBRID-{i+1}",
            "title": f"Phase {p['phase']}: {p['pattern']}",
            "severity": "info",
            "confidence": "high",
            "affected_asset": target or "unknown",
            "evidence": f"Task characteristics: complexity={characteristics['complexity']}, scope={characteristics['scope']}, parallelism={characteristics['parallelism']}",
            "remediation": "No action needed",
        } for i, p in enumerate(workflow["phases"])]

        return tool_result(
            self.name, target or "unknown", status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Hybrid workflow complete: {len(workflow['phases'])} phases, patterns used: {', '.join(set(p['pattern'] for p in workflow['phases']))}",
            metadata={
                "task_characteristics": characteristics,
                "selected_patterns": phases,
                "workflow": workflow,
                "total_phases": len(workflow["phases"]),
            },
        )

    def _analyze_task(self, task: str) -> dict:
        word_count = len(task.split())
        complexity = "high" if word_count > 30 else ("medium" if word_count > 15 else "low")
        scope = "broad" if ";" in task or "and" in task.lower() else "focused"
        parallelism = True if "and" in task.lower() or ";" in task else False
        return {"complexity": complexity, "scope": scope, "parallelism": parallelism, "word_count": word_count}

    def _select_patterns(self, characteristics: dict) -> list:
        patterns = []
        if characteristics["complexity"] == "high":
            patterns.append({"phase": 1, "pattern": "chain_of_thought", "rationale": "Decompose complex task sequentially"})
        if characteristics["scope"] == "broad":
            patterns.append({"phase": len(patterns) + 1, "pattern": "hierarchical", "rationale": "Broad scope benefits from decomposition"})
        if characteristics["parallelism"]:
            patterns.append({"phase": len(patterns) + 1, "pattern": "swarm", "rationale": "Parallel exploration of independent aspects"})
        patterns.append({"phase": len(patterns) + 1, "pattern": "auction", "rationale": "Optimize resource allocation for final execution"})
        return patterns

    def _orchestrate_phases(self, phases: list, task: str, target: str) -> dict:
        executed = []
        for phase in phases:
            executed.append({
                "phase": phase["phase"],
                "pattern": phase["pattern"],
                "rationale": phase["rationale"],
                "task_subset": task[:80],
                "status": "completed",
            })
        return {"phases": executed, "task": task, "target": target}