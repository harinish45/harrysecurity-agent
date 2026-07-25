from nexus.agents.base_agent import BaseAgent
from nexus.reporting.generator import ReportGenerator
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ReporterAgent(BaseAgent):
    name = "reporter_agent"
    description = "support agent for report generation — creates executive summaries and formatted reports"

    async def run(self, task: str, target: str = "", findings: list = None, mission_id: str = "assessment", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = findings or []

        # Generate report
        generator = ReportGenerator()
        report = generator.generate(
            findings,
            target=target,
            mission_id=mission_id,
        )

        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Write report to file
        from pathlib import Path
        import re
        safe_mission = re.sub(r"[^A-Za-z0-9_.-]+", "-", mission_id).strip(".-") or "assessment"
        report_path = generator.write(report, Path("reports") / f"{safe_mission}.md")

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Report generated for {target}: {len(findings)} findings, saved to {report_path}",
            metadata={
                "report_path": str(report_path),
                "severity_counts": severity_counts,
                "total_findings": len(findings),
                "mission_id": mission_id,
            },
        )