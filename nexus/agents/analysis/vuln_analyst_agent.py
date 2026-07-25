from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class VulnAnalystAgent(BaseAgent):
    name = "vuln_analyst_agent"
    description = "analysis agent for vulnerability analysis — triages and prioritizes findings"

    async def run(self, task: str, target: str = "", findings: list = None, **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = findings or []
        analysis = []

        # Prioritize findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 4),
        )

        # Generate analysis for each finding
        for f in sorted_findings:
            sev = f.get("severity", "info")
            title = f.get("title", "Untitled")
            evidence = f.get("evidence", "")
            remediation = f.get("remediation", "")
            confidence = f.get("confidence", "medium")

            analysis.append({
                "id": f.get("id", "F-???"),
                "title": title,
                "severity": sev,
                "confidence": confidence,
                "priority": "P1" if sev in ("critical", "high") else ("P2" if sev == "medium" else "P3"),
                "evidence": evidence,
                "remediation": remediation,
                "affected_asset": f.get("affected_asset", target),
            })

        # Generate summary statistics
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        risk_score = min(10.0, round(
            (counts["critical"] * 10 + counts["high"] * 7 + counts["medium"] * 4 + counts["low"] * 1) / max(1, len(findings)) * 2.5, 1
        ))

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Vulnerability analysis for {target}: {len(findings)} findings, risk score {risk_score}/10",
            metadata={
                "analysis": analysis,
                "severity_counts": counts,
                "risk_score": risk_score,
                "total_findings": len(findings),
            },
        )