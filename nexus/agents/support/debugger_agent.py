from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class DebuggerAgent(BaseAgent):
    name = "debugger_agent"
    description = "support agent for debugging — analyzes errors, traces execution, and identifies root causes"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        findings = []
        tools_used = []
        task_lower = task.lower()

        if any(w in task_lower for w in ["error", "trace", "debug", "crash", "exception", "stack"]):
            try:
                result = tool_registry.run("reverse_engineering.debugging", task=task, target=target)
                tools_used.append("reverse_engineering.debugging")
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"Debugging error: {e}", "severity": "low", "confidence": "medium"})

        if any(w in task_lower for w in ["memory", "dump", "forensics", "leak"]):
            try:
                result = tool_registry.run("forensics.memory_forensics", task=task, target=target)
                tools_used.append("forensics.memory_forensics")
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"Memory forensics error: {e}", "severity": "low", "confidence": "medium"})

        if any(w in task_lower for w in ["malware", "behavior", "api", "monitor"]):
            for tool_name in ("malware.behavior_analysis", "malware.api_monitoring"):
                try:
                    result = tool_registry.run(tool_name, task=task, target=target)
                    tools_used.append(tool_name)
                    if result.get("findings"):
                        findings.extend(result["findings"])
                except Exception as e:
                    findings.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        root_causes = [f for f in findings if "error" in f.get("title", "").lower() or "cause" in f.get("title", "").lower()]
        suggested_fixes = [
            "Review stack trace and identify failing function",
            "Check input validation and error handling",
            "Verify environment variables and configuration",
            "Enable verbose logging for additional context",
        ]

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Debug analysis completed: {len(findings)} findings, {len(root_causes)} potential root causes identified",
            metadata={
                "tools_used": tools_used,
                "root_causes": root_causes,
                "suggested_fixes": suggested_fixes,
                "execution_traced": len(tools_used) > 0,
            },
        )
