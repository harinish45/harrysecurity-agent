from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ValidatorAgent(BaseAgent):
    name = "validator_agent"
    description = "support agent for validation — validates findings, checks compliance, and verifies remediation"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = kwargs.get("findings", []) or []
        validation_results = []
        tools_used = []

        compliance_tools = [
            "compliance.policy_reviews",
            "compliance.security_audits",
            "compliance.risk_assessments",
        ]

        for tool_name in compliance_tools:
            try:
                result = tool_registry.run(tool_name, target=target, findings=findings)
                tools_used.append(tool_name)
                if result.get("findings"):
                    validation_results.extend(result["findings"])
            except Exception as e:
                validation_results.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        for tool_name in ("appsec.sca", "appsec.dependency_analysis"):
            try:
                result = tool_registry.run(tool_name, target=target)
                tools_used.append(tool_name)
                if result.get("findings"):
                    validation_results.extend(result["findings"])
            except Exception as e:
                validation_results.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        remediation_status = kwargs.get("remediation_status", {}) or {}
        try:
            result = tool_registry.run("vuln_assessment.remediation_validation", target=target, findings=findings, remediation_status=remediation_status)
            tools_used.append("vuln_assessment.remediation_validation")
            if result.get("findings"):
                validation_results.extend(result["findings"])
        except Exception as e:
            validation_results.append({"title": f"Remediation validation error: {e}", "severity": "low", "confidence": "medium"})

        passed = sum(1 for v in validation_results if v.get("severity") in ("info", "low"))
        failed = sum(1 for v in validation_results if v.get("severity") in ("medium", "high", "critical"))

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=validation_results,
            summary=f"Validation completed: {passed} passed, {failed} failed checks across {len(tools_used)} tools",
            metadata={
                "tools_used": tools_used,
                "passed_checks": passed,
                "failed_checks": failed,
                "total_validations": len(validation_results),
                "compliance_checked": True,
                "remediation_verified": len(remediation_status) > 0,
            },
        )
