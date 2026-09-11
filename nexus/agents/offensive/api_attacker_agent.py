from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ApiAttackerAgent(BaseAgent):
    name = "api_attacker_agent"
    description = "offensive agent for API attacks — REST API testing, API security, and rate limit testing"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("webapp.api_security", target=target)
            tools_used.append("webapp.api_security")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"API security error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("webapp.rest_api_testing", target=target)
            tools_used.append("webapp.rest_api_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"REST API testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("webapp.browser_agent", target=target)
            tools_used.append("webapp.browser_agent")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Browser agent error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("webapp.rate_limit", target=target)
            tools_used.append("webapp.rate_limit")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Rate limit testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("webapp.auth_test", target=target)
            tools_used.append("webapp.auth_test")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Auth test error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"API attack testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )