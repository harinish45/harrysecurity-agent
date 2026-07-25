from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class WebAppAgent(BaseAgent):
    name = "webapp_agent"
    description = "offensive agent for web application testing — SQLi, XSS, SSRF, LFI, command injection"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # SQL Injection testing
        try:
            sqli = tool_registry.get("webapp.sqli")
            result = sqli(target=target)
            tools_used.append("webapp.sqli")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SQLi test error: {e}", "severity": "low", "confidence": "medium"})

        # XSS testing
        try:
            xss = tool_registry.get("webapp.xss")
            result = xss(target=target)
            tools_used.append("webapp.xss")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"XSS test error: {e}", "severity": "low", "confidence": "medium"})

        # SSRF testing
        try:
            ssrf = tool_registry.get("webapp.ssrf")
            result = ssrf(target=target)
            tools_used.append("webapp.ssrf")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SSRF test error: {e}", "severity": "low", "confidence": "medium"})

        # LFI testing
        try:
            lfi = tool_registry.get("webapp.lfi")
            result = lfi(target=target)
            tools_used.append("webapp.lfi")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"LFI test error: {e}", "severity": "low", "confidence": "medium"})

        # Command injection testing
        try:
            cmdi = tool_registry.get("webapp.cmdi")
            result = cmdi(target=target)
            tools_used.append("webapp.cmdi")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"CMDi test error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Web app testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
