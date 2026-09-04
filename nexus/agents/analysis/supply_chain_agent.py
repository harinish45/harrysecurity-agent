from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class SupplyChainAgent(BaseAgent):
    name = "supply_chain_agent"
    description = "analysis agent for supply chain — SCA, dependency analysis, and patch verification"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # SCA
        try:
            result = tool_registry.run("appsec.sca", target=target)
            tools_used.append("appsec.sca")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"SCA error: {e}", "severity": "low", "confidence": "medium"})

        # Dependency analysis
        try:
            result = tool_registry.run("appsec.dependency_analysis", target=target)
            tools_used.append("appsec.dependency_analysis")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Dependency analysis error: {e}", "severity": "low", "confidence": "medium"})

        # CI/CD security
        try:
            result = tool_registry.run("appsec.cicd_security", target=target)
            tools_used.append("appsec.cicd_security")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"CI/CD security error: {e}", "severity": "low", "confidence": "medium"})

        # Patch verification
        try:
            result = tool_registry.run("vuln_assessment.patch_verification", target=target)
            tools_used.append("vuln_assessment.patch_verification")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Patch verification error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Supply chain analysis completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
