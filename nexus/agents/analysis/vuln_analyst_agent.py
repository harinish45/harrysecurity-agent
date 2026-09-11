from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, tool_result


class VulnAnalystAgent(BaseAgent):
    name = "vuln_analyst_agent"
    description = "Vulnerability analysis agent that correlates findings and identifies risk patterns"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, "unknown", status=STATUS_FAILED, error="No target specified")

        findings = kwargs.get("findings", []) or []
        findings_out = []

        # network_vuln_scanning/web_vuln_scanning/cve_analysis are the real
        # registered vuln_assessment.* tools — this used to call
        # "vuln_assessment.vuln_scan"/".cve_lookup", neither of which was
        # ever registered anywhere, so every real run silently skipped both
        # and this agent (which the default mission plan in
        # OrchestrationEngine._plan_mission falls back to for its P4 phase)
        # never actually scanned anything.
        for tool_name in ("vuln_assessment.network_vuln_scanning", "vuln_assessment.web_vuln_scanning",
                          "vuln_assessment.cve_analysis"):
            try:
                result = tool_registry.run(tool_name, target=target)
                if result.get("findings"):
                    findings_out.extend(result["findings"])
            except Exception as e:
                findings_out.append({"title": f"{tool_name} error: {e}", "severity": "low", "confidence": "medium"})

        # Analyze existing (upstream) findings for risk patterns
        if findings:
            high_risk = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")]
            if high_risk:
                findings_out.append({
                    "title": f"Risk analysis: {len(high_risk)} high/critical severity finding(s) identified",
                    "severity": "info", "confidence": "high",
                })

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=findings_out,
            summary=f"Vulnerability analysis for {target}: {len(findings_out)} finding(s), "
                    f"{len(findings)} upstream finding(s) correlated",
        )
