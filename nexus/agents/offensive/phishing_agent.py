from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class PhishingAgent(BaseAgent):
    name = "phishing_agent"
    description = "offensive agent for phishing — email harvesting, social engineering, and session analysis"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("webapp.auth_test", target=target)
            tools_used.append("webapp.auth_test")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Auth test error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("webapp.session_mgmt", target=target)
            tools_used.append("webapp.session_mgmt")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Session management error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("reconnaissance.email_harvest", target=target)
            tools_used.append("reconnaissance.email_harvest")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Email harvesting error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("reconnaissance.social_osint", target=target)
            tools_used.append("reconnaissance.social_osint")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Social OSINT error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("webapp.business_logic", target=target)
            tools_used.append("webapp.business_logic")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Business logic error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Phishing testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )