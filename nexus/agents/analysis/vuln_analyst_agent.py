from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry

class VulnAnalystAgent(BaseAgent):
    name = "vuln_analyst_agent"
    description = "Vulnerability analysis agent that correlates findings and identifies risk patterns"

    async def run(self, task: str, **kwargs) -> dict:
        target = kwargs.get("target", "")
        findings = kwargs.get("findings", [])
        findings_out = []
        
        # Run vulnerability assessment tools
        for tool_name in ["vuln_assessment.vuln_scan", "vuln_assessment.cve_lookup"]:
            try:
                tool_fn = tool_registry.get(tool_name)
                result = tool_fn(target=target)
                if result.get("findings"):
                    findings_out.extend(result["findings"])
            except (KeyError, Exception) as e:
                findings_out.append(f"[{tool_name}] skipped: {e}")
        
        # Analyze existing findings for risk patterns
        if findings:
            high_risk = [f for f in findings if "critical" in str(f).lower() or "high" in str(f).lower()]
            if high_risk:
                findings_out.append(f"Risk analysis: {len(high_risk)} high/critical severity findings identified")
            findings_out.append(f"Total findings analyzed: {len(findings)}")
        
        if not findings_out:
            findings_out.append(f"Vulnerability analysis completed for {target}: no specific vulnerabilities identified")

        return {"agent": self.name, "task": task, "tier": "analysis", 
                "status": "completed", "findings": findings_out}