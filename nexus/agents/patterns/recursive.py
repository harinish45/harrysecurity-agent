from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class RecursivePattern(BaseAgent):
    name = "recursive_pattern"
    description = "agent pattern for recursive problem-solving — breaks problems into subproblems and solves recursively"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        solution_tree = self._solve_recursive(task, depth=0, max_depth=3)
        findings = [{
            "id": f"RECUR-{i+1}",
            "title": f"Node '{node['task'][:40]}' (depth {node['depth']})",
            "severity": "info",
            "confidence": "high",
            "affected_asset": target or "unknown",
            "evidence": f"Result: {node['result']}",
            "remediation": "No action needed",
        } for i, node in enumerate(solution_tree["nodes"])]

        return tool_result(
            self.name, target or "unknown", status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Recursive decomposition complete: {solution_tree['total_nodes']} nodes, depth {solution_tree['max_depth']}",
            metadata={
                "solution_tree": solution_tree,
                "total_nodes": solution_tree["total_nodes"],
                "max_depth": solution_tree["max_depth"],
            },
        )

    def _solve_recursive(self, task: str, depth: int, max_depth: int) -> dict:
        nodes = []
        is_base = depth >= max_depth or len(task.split()) <= 5
        if is_base:
            result = f"Base case: solved '{task[:40]}' directly at depth {depth}"
            nodes.append({"task": task, "depth": depth, "result": result, "children": []})
            return {"nodes": nodes, "total_nodes": 1, "max_depth": depth}

        result = f"Decomposed '{task[:40]}' at depth {depth}"
        node = {"task": task, "depth": depth, "result": result, "children": []}
        total = 1
        max_d = depth
        subproblems = self._split_task(task)
        for sub in subproblems:
            child = self._solve_recursive(sub, depth + 1, max_depth)
            nodes.extend(child["nodes"])
            total += child["total_nodes"]
            max_d = max(max_d, child["max_depth"])
            node["children"].append(sub)
        return {"nodes": nodes, "total_nodes": total, "max_depth": max_d}

    def _split_task(self, task: str) -> list:
        parts = [p.strip() for p in task.replace(";", ",").split(",") if p.strip()]
        if len(parts) <= 1:
            words = task.split()
            mid = max(1, len(words) // 2)
            return [" ".join(words[:mid]), " ".join(words[mid:])]
        return parts[:4]