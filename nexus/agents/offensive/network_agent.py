from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class NetworkAgent(BaseAgent):
    name = "network_agent"
    description = "offensive agent for network testing — port scan, service enum, host discovery, OS fingerprint"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []

        # Host discovery
        try:
            host_disc = tool_registry.get("network.host_discovery")
            result = host_disc(target=target)
            tools_used.append("network.host_discovery")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Host discovery error: {e}", "severity": "low", "confidence": "medium"})

        # Port scanning
        try:
            port_scan = tool_registry.get("network.port_scan")
            result = port_scan(target=target)
            tools_used.append("network.port_scan")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Port scan error: {e}", "severity": "low", "confidence": "medium"})

        # Service enumeration
        try:
            svc_enum = tool_registry.get("network.service_enum")
            result = svc_enum(target=target)
            tools_used.append("network.service_enum")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Service enum error: {e}", "severity": "low", "confidence": "medium"})

        # Banner grabbing
        try:
            banner = tool_registry.get("network.banner_grab")
            result = banner(target=target)
            tools_used.append("network.banner_grab")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"Banner grab error: {e}", "severity": "low", "confidence": "medium"})

        # OS fingerprinting
        try:
            os_fp = tool_registry.get("network.os_fingerprint")
            result = os_fp(target=target)
            tools_used.append("network.os_fingerprint")
            if result.get("findings"):
                findings.extend(result["findings"])
        except Exception as e:
            findings.append({"title": f"OS fingerprint error: {e}", "severity": "low", "confidence": "medium"})

        status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
        return tool_result(
            self.name, target,
            status=status,
            findings=findings,
            summary=f"Network testing completed for {target} using {len(tools_used)} tools, {len(findings)} findings",
            metadata={"tools_used": tools_used},
        )