from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, tool_result

class ReconAgent(BaseAgent):
    name = "recon_agent"
    description = "Reconnaissance agent that performs host discovery, DNS resolution, and OSINT"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []

        # Run reconnaissance tools from the registry
        for tool_name in ["reconnaissance.dns_recon", "reconnaissance.subdomain_enum",
                          "reconnaissance.tech_fingerprint", "reconnaissance.whois_lookup"]:
            try:
                result = tool_registry.run(tool_name, target=target)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{tool_name} skipped: {e}", "severity": "low", "confidence": "medium"})

        if not findings:
            # Fallback: basic DNS resolution
            import socket
            try:
                ip = socket.gethostbyname(target)
                findings.append({"title": f"Resolved {target} -> {ip}", "severity": "info", "confidence": "certain"})
            except Exception as e:
                findings.append({"title": f"DNS resolution failed: {e}", "severity": "low", "confidence": "medium"})

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Reconnaissance on {target}: {len(findings)} finding(s)",
        )