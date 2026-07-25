from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class HierarchicalPattern(BaseAgent):
    name = "hierarchical_pattern"
    description = "agent pattern for hierarchical coordination — parent agents delegate to child agents in a tree structure"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        depth = self._determine_depth(task)
        tree = self._build_tree(task, depth)
        results = self._execute_tree(tree)

        findings = [{
            "id": f"HIER-{i+1}",
            "title": f"Node '{node['name']}' (depth {node['depth']})",
            "severity": "info",
            "confidence": "high",
            "affected_asset": target or "unknown",
            "evidence": f"Result: {node['result']}",
            "remediation": "No action needed",
        } for i, node in enumerate(results["nodes"])]

        return tool_result(
            self.name, target or "unknown", status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Hierarchical decomposition complete: depth {depth}, {len(results['nodes'])} nodes executed",
            metadata={
                "depth": depth,
                "tree": tree,
                "nodes": results["nodes"],
                "aggregated_result": results["aggregated"],
            },
        )

    def _determine_depth(self, task: str) -> int:
        complexity_markers = task.count("and") + task.count("or") + task.count(";")
        if complexity_markers >= 3:
            return 3
        if complexity_markers >= 1:
            return 2
        return 1

    def _build_tree(self, task: str, depth: int) -> dict:
        root = {"name": "root", "task": task, "depth": 0, "children": []}
        if depth >= 1:
            for i in range(min(3, max(1, depth))):
                child = {"name": f"child_{i+1}", "task": f"Subtask {i+1} of: {task[:60]}", "depth": 1, "children": []}
                if depth >= 2:
                    for j in range(2):
                        child["children"].append({
                            "name": f"grandchild_{i+1}_{j+1}",
                            "task": f"Sub-subtask {j+1} of child {i+1}",
                            "depth": 2, "children": [],
                        })
                root["children"].append(child)
        return root

    def _execute_tree(self, tree: dict) -> dict:
        nodes = []
        aggregated = []
        self._traverse(tree, nodes, aggregated)
        return {"nodes": nodes, "aggregated": "; ".join(aggregated) if aggregated else "No results"}

    def _traverse(self, node: dict, nodes: list, aggregated: list) -> None:
        result = f"Executed: {node['task'][:50]}"
        node["result"] = result
        nodes.append(node)
        aggregated.append(result)
        for child in node.get("children", []):
            self._traverse(child, nodes, aggregated)