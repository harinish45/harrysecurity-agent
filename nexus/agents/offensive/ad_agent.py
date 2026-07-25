from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class AdAgent(BaseAgent):
    name = "ad_agent"
    description = "offensive agent for active directory — domain enum, Kerberoasting, AS-REP roasting, pass-the-hash, and golden ticket attacks"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        try:
            tool = tool_registry.get("active_directory.domain_enum")
            result = tool(target=target)
            tools_used.append("active_directory.domain_enum")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Domain enum error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("active_directory.bloodhound")
            result = tool(target=target)
            tools_used.append("active_directory.bloodhound")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"BloodHound error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("active_directory.kerberoast")
            result = tool(target=target)
            tools_used.append("active_directory.kerberoast")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Kerberoasting error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("active_directory.asrep_roast")
            result = tool(target=target)
            tools_used.append("active_directory.asrep_roast")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"AS-REP roasting error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("active_directory.pass_the_hash")
            result = tool(target=target)
            tools_used.append("active_directory.pass_the_hash")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Pass-the-hash error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("active_directory.golden_ticket")
            result = tool(target=target)
            tools_used.append("active_directory.golden_ticket")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Golden ticket error: {e}", "severity": "low", "confidence": "medium"})

        try:
            tool = tool_registry.get("active_directory.pass_the_ticket")
            result = tool(target=target)
            tools_used.append("active_directory.pass_the_ticket")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Pass-the-ticket error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Active Directory testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )