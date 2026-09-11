from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class AiSecurityAgent(BaseAgent):
    name = "ai_security_agent"
    description = "specialized agent for AI security — adversarial ML, prompt injection, AI red teaming, and model evaluation"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            result = tool_registry.run("ai_security.adversarial_ml", target=target)
            tools_used.append("ai_security.adversarial_ml")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Adversarial ML error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("ai_security.llm_prompt_injection_testing", target=target)
            tools_used.append("ai_security.llm_prompt_injection_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"LLM prompt injection testing error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("ai_security.ai_red_teaming", target=target)
            tools_used.append("ai_security.ai_red_teaming")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"AI red teaming error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("ai_security.model_evaluation", target=target)
            tools_used.append("ai_security.model_evaluation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Model evaluation error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("ai_security.data_poisoning_research", target=target)
            tools_used.append("ai_security.data_poisoning_research")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Data poisoning research error: {e}", "severity": "low", "confidence": "medium"})

        try:
            result = tool_registry.run("ai_security.model_extraction_testing", target=target)
            tools_used.append("ai_security.model_extraction_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Model extraction testing error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"AI security testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )