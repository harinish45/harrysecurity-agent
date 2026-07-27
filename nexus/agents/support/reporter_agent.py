from nexus.agents.base_agent import BaseAgent

class ReporterAgent(BaseAgent):
    name = "reporter_agent"
    description = "Report generation agent that produces structured security assessment reports"

    async def run(self, task: str, **kwargs) -> dict:
        target = kwargs.get("target", "")
        findings = kwargs.get("findings", [])
        findings_out = []
        
        from datetime import datetime
        
        # Generate summary report
        report_lines = []
        report_lines.append(f"# Security Assessment Report: {target}")
        report_lines.append(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"**Target**: {target}")
        report_lines.append("")
        
        if findings:
            # Categorize findings
            critical = [f for f in findings if "critical" in str(f).lower()]
            high = [f for f in findings if "high" in str(f).lower() and "critical" not in str(f).lower()]
            medium = [f for f in findings if "medium" in str(f).lower() and "high" not in str(f).lower()]
            
            report_lines.append("## Executive Summary")
            report_lines.append(f"- **{len(critical)}** Critical severity issues")
            report_lines.append(f"- **{len(high)}** High severity issues")
            report_lines.append(f"- **{len(medium)}** Medium severity issues")
            report_lines.append(f"- **{len(findings)}** Total findings")
            report_lines.append("")
            
            if critical:
                report_lines.append("## Critical Findings")
                for f in critical:
                    report_lines.append(f"- 🔴 {f}")
                report_lines.append("")
            
            if high:
                report_lines.append("## High Severity Findings")
                for f in high:
                    report_lines.append(f"- 🟠 {f}")
                report_lines.append("")
            
            report_lines.append("## All Findings")
            for i, f in enumerate(findings, 1):
                report_lines.append(f"{i}. {f}")
        else:
            report_lines.append("No findings were discovered during this assessment.")
        
        report = "\n".join(report_lines)
        findings_out.append(f"Report generated: {len(findings)} findings documented")
        
        # Save report to file
        import os
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)
        safe_target = target.replace(":", "_").replace("/", "_").replace(".", "_")
        report_path = os.path.join(reports_dir, f"report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
            findings_out.append(f"Report saved to: {report_path}")
        except Exception as e:
            findings_out.append(f"Could not save report: {e}")

        return {"agent": self.name, "task": task, "tier": "support", 
                "status": "completed", "findings": findings_out, "report": report}