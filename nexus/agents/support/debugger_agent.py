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
        suggested_fixes = self._suggest_fixes(task_lower, tools_used, root_causes)

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

    @staticmethod
    def _suggest_fixes(task_lower: str, tools_used: list, root_causes: list) -> list:
        """Rule-based, conditioned on what was actually investigated —
        not a fixed list returned unconditionally regardless of task/findings."""
        fixes = []
        if "reverse_engineering.debugging" in tools_used:
            fixes.append("Review the stack trace at the failing frame and confirm inputs match its preconditions")
        if "forensics.memory_forensics" in tools_used:
            fixes.append("Check for unclosed handles/references around the flagged allocation and confirm it's released on every code path")
        if "malware.behavior_analysis" in tools_used or "malware.api_monitoring" in tools_used:
            fixes.append("Diff observed API/behavior sequence against the expected baseline for this component")
        if root_causes:
            fixes.append(f"Start with the {len(root_causes)} finding(s) flagged as a likely root cause before broader investigation")
        if not fixes:
            fixes.append("No debugging-specific tool matched this task — narrow the task description (error/trace, memory/leak, or malware/behavior) to run a targeted check")
        return fixes
