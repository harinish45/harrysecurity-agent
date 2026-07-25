from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class DetectionEngineerAgent(BaseAgent):
    name = "detection_engineer_agent"
    description = "defensive agent for detection engineering — rule tuning, detection testing, and SOC engineering"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Detection engineering (blue team)
        try:
            det_blue = tool_registry.get("blue_team.detection_engineering_blue")
            result = det_blue(target=target)
            tools_used.append("blue_team.detection_engineering_blue")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Blue team detection engineering error: {e}", "severity": "low", "confidence": "medium"})

        # Rule tuning
        try:
            tune = tool_registry.get("soc.rule_tuning")
            result = tune(target=target)
            tools_used.append("soc.rule_tuning")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Rule tuning error: {e}", "severity": "low", "confidence": "medium"})

        # Detection engineering (SOC)
        try:
            det_soc = tool_registry.get("soc.detection_engineering_soc")
            result = det_soc(target=target)
            tools_used.append("soc.detection_engineering_soc")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SOC detection engineering error: {e}", "severity": "low", "confidence": "medium"})

        # Detection testing
        try:
            det_test = tool_registry.get("purple_team.detection_testing")
            result = det_test(target=target)
            tools_used.append("purple_team.detection_testing")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Detection testing error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Detection engineering completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
