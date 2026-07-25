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
            disk = tool_registry.get("forensics.disk_forensics")
            result = disk(target=target)
            tools_used.append("forensics.disk_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Disk forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Memory forensics
        try:
            mem = tool_registry.get("forensics.memory_forensics")
            result = mem(target=target)
            tools_used.append("forensics.memory_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Memory forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Browser forensics
        try:
            browser = tool_registry.get("forensics.browser_forensics")
            result = browser(target=target)
            tools_used.append("forensics.browser_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Browser forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Log analysis
        try:
            log = tool_registry.get("forensics.log_analysis")
            result = log(target=target)
            tools_used.append("forensics.log_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Log analysis error: {e}", "severity": "low", "confidence": "medium"})

        # Network forensics
        try:
            net = tool_registry.get("forensics.network_forensics")
            result = net(target=target)
            tools_used.append("forensics.network_forensics")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Network forensics error: {e}", "severity": "low", "confidence": "medium"})

        # Email forensics
        try:
            email = tool_registry.get("forensics.email_forensics")
            result = email(target=target)
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
