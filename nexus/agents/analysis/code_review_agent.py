from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry


class CodeReviewAgent(BaseAgent):
    name = "code_review_agent"
    description = "analysis agent for code review — static analysis, secret scanning, and dependency review"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("appsec.sast", target=target)
            tools_used.append("appsec.sast")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"SAST error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("appsec.secure_code_review", target=target)
            tools_used.append("appsec.secure_code_review")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"Secure code review error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("appsec.secret_scanning", target=target)
            tools_used.append("appsec.secret_scanning")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"Secret scanning error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("appsec.sca", target=target)
            tools_used.append("appsec.sca")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:  # noqa: BLE001
            findings.append({"title": f"SCA error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name,
            target,
            status=status,
            findings=findings,
            summary=f"Code review completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
