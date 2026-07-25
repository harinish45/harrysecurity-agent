from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class QualityAssessorAgent(BaseAgent):
    name = "quality_assessor_agent"
    description = "orchestrator agent for quality assessment — evaluates findings quality and assigns risk scores"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = kwargs.get("findings", []) or []
        if not findings:
            return tool_result(self.name, target, status=STATUS_NO_FINDINGS, summary="No findings provided for quality assessment")

        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        confidence_weights = {"certain": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "tentative": 0.1}

        validated = []
        total_risk = 0.0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for f in findings:
            sev = f.get("severity", "info")
            conf = f.get("confidence", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            weight = severity_weights.get(sev, 0) * confidence_weights.get(conf, 0.5)
            total_risk += weight
            validated.append({
                "id": f.get("id", "F-???"),
                "title": f.get("title", "Untitled"),
                "severity": sev,
                "confidence": conf,
                "risk_score": round(weight, 2),
                "validation_status": "validated" if weight >= 3.0 else "review",
            })

        try:
            risk_tool = tool_registry.get("vuln_assessment.risk_scoring")
            risk_result = risk_tool(target=target, findings=findings)
            if risk_result.get("findings"):
                validated.extend(risk_result["findings"])
        except Exception as e:
            validated.append({"title": f"Risk scoring error: {e}", "severity": "low", "confidence": "medium"})

        try:
            prior_tool = tool_registry.get("vuln_assessment.prioritization")
            prior_result = prior_tool(target=target, findings=findings)
            if prior_result.get("findings"):
                validated.extend(prior_result["findings"])
        except Exception as e:
            validated.append({"title": f"Prioritization error: {e}", "severity": "low", "confidence": "medium"})

        max_possible = len(findings) * 10
        overall_risk = round((total_risk / max_possible) * 10, 1) if max_possible > 0 else 0.0

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Quality assessment for {target}: {len(findings)} findings, overall risk score {overall_risk}/10",
            metadata={
                "validated_findings": validated,
                "severity_counts": severity_counts,
                "overall_risk_score": overall_risk,
                "total_findings": len(findings),
                "validation_summary": {
                    "validated": sum(1 for v in validated if v.get("validation_status") == "validated"),
                    "review": sum(1 for v in validated if v.get("validation_status") == "review"),
                },
            },
        )
