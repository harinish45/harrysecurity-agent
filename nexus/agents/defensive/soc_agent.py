from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class SocAgent(BaseAgent):
    name = "soc_agent"
    description = "defensive agent for SOC operations — alert investigation, log correlation, and SIEM monitoring"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Alert investigation
        try:
            result = tool_registry.run("soc.alert_investigation", target=target)
            tools_used.append("soc.alert_investigation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Alert investigation error: {e}", "severity": "low", "confidence": "medium"})

        # Log correlation
        try:
            result = tool_registry.run("soc.log_correlation", target=target)
            tools_used.append("soc.log_correlation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Log correlation error: {e}", "severity": "low", "confidence": "medium"})

        # SIEM monitoring
        try:
            result = tool_registry.run("soc.siem_monitoring", target=target)
            tools_used.append("soc.siem_monitoring")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SIEM monitoring error: {e}", "severity": "low", "confidence": "medium"})

        # SOAR automation
        try:
            result = tool_registry.run("soc.soar_automation", target=target)
            tools_used.append("soc.soar_automation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SOAR automation error: {e}", "severity": "low", "confidence": "medium"})

        # Dashboard creation
        try:
            result = tool_registry.run("soc.dashboard_creation", target=target)
            tools_used.append("soc.dashboard_creation")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Dashboard creation error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"SOC operations completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
