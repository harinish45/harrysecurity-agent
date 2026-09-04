from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ForensicsAgent(BaseAgent):
    name = "forensics_agent"
    description = "analysis agent for forensics — disk, memory, browser, and log analysis"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Disk forensics
        try:
            result = tool_registry.run("forensics.disk_forensics", target=target)
            tools_used.append("forensics.disk_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Disk forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Memory forensics
        try:
            result = tool_registry.run("forensics.memory_forensics", target=target)
            tools_used.append("forensics.memory_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Memory forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Browser forensics
        try:
            result = tool_registry.run("forensics.browser_forensics", target=target)
            tools_used.append("forensics.browser_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Browser forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Log analysis
        try:
            result = tool_registry.run("forensics.log_analysis", target=target)
            tools_used.append("forensics.log_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Log analysis error: {e}", "severity": "low", "confidence": "medium"})

        # Network forensics
        try:
            result = tool_registry.run("forensics.network_forensics", target=target)
            tools_used.append("forensics.network_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Network forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Email forensics
        try:
            result = tool_registry.run("forensics.email_forensics", target=target)
            tools_used.append("forensics.email_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Email forensics error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Forensics analysis completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
