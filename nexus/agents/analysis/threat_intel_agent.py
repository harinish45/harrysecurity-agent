from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class ThreatIntelAgent(BaseAgent):
    name = "threat_intel_agent"
    description = "analysis agent for threat intelligence — threat feeds, IOC enrichment, and ATT&CK mapping"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Threat feeds
        try:
            result = tool_registry.run("threat_intel.threat_feeds", target=target)
            tools_used.append("threat_intel.threat_feeds")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Threat feeds error: {e}", "severity": "low", "confidence": "medium"})

        # IOC enrichment
        try:
            result = tool_registry.run("threat_intel.ioc_enrichment", target=target)
            tools_used.append("threat_intel.ioc_enrichment")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"IOC enrichment error: {e}", "severity": "low", "confidence": "medium"})

        # Threat actor profiling
        try:
            result = tool_registry.run("threat_intel.threat_actor_profiling", target=target)
            tools_used.append("threat_intel.threat_actor_profiling")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Threat actor profiling error: {e}", "severity": "low", "confidence": "medium"})

        # ATT&CK mapping
        try:
            result = tool_registry.run("threat_intel.attck_mapping", target=target)
            tools_used.append("threat_intel.attck_mapping")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"ATT&CK mapping error: {e}", "severity": "low", "confidence": "medium"})

        # Malware family tracking
        try:
            result = tool_registry.run("threat_intel.malware_family_tracking", target=target)
            tools_used.append("threat_intel.malware_family_tracking")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Malware family tracking error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Threat intelligence analysis completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )
