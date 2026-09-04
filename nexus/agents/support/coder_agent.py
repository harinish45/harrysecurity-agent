from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class CoderAgent(BaseAgent):
    name = "coder_agent"
    description = "support agent for coding — generates scripts, custom tools, and performs code review"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not task:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No task specified")

        findings = []
        tools_used = []
        task_lower = task.lower()
        generated_code = ""
        review_issues = []

        if any(w in task_lower for w in ["generate", "create", "write", "script", "tool", "automation"]):
            try:
                result = tool_registry.run("automation.python_scripting", task=task, target=target)
                tools_used.append("automation.python_scripting")
                if result.get("findings"):
                    findings.extend(result["findings"])
                generated_code = result.get("metadata", {}).get("code", "# Script generation placeholder")
            except Exception as e:
                findings.append({"title": f"Script generation error: {e}", "severity": "low", "confidence": "medium"})

        if any(w in task_lower for w in ["review", "audit", "secure", "scan", "secret"]):
            for tool_name in ("appsec.secure_code_review", "appsec.secret_scanning"):
                try:
                    result = tool_registry.run(tool_name, target=target or "codebase")
                    tools_used.append(tool_name)
                    if result.get("findings"):
                        review_issues.extend(result["findings"])
                        findings.extend(result["findings"])
                except Exception as e:
                    findings.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        if not tools_used and any(w in task_lower for w in ["custom", "develop", "build"]):
            try:
                result = tool_registry.run("automation.custom_tool_development", task=task, target=target)
                tools_used.append("automation.custom_tool_development")
                if result.get("findings"):
                    findings.extend(result["findings"])
                generated_code = result.get("metadata", {}).get("code", "# Custom tool placeholder")
            except Exception as e:
                findings.append({"title": f"Custom tool development error: {e}", "severity": "low", "confidence": "medium"})

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Coding task completed: {len(tools_used)} tools used, {len(findings)} findings, {len(review_issues)} code issues",
            metadata={
                "tools_used": tools_used,
                "generated_code": generated_code,
                "review_issues": review_issues,
                "task_type": "generation" if generated_code else "review",
            },
        )
