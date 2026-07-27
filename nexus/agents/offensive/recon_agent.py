from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry

class ReconAgent(BaseAgent):
    name = "recon_agent"
    description = "Reconnaissance agent that performs host discovery, DNS resolution, and OSINT"

    async def run(self, task: str, **kwargs) -> dict:
        target = kwargs.get("target", "")
        findings = []
        
        # Run reconnaissance tools from the registry
        for tool_name in ["reconnaissance.dns_recon", "reconnaissance.subdomain_enum", 
                          "reconnaissance.tech_fingerprint", "reconnaissance.whois_lookup"]:
            try:
                tool_fn = tool_registry.get(tool_name)
                result = tool_fn(target=target)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except (KeyError, Exception) as e:
                findings.append(f"[{tool_name}] skipped: {e}")
        
        if not findings:
            # Fallback: basic DNS resolution
            import socket
            try:
                ip = socket.gethostbyname(target)
                findings.append(f"Resolved {target} -> {ip}")
            except Exception as e:
                findings.append(f"DNS resolution failed: {e}")

        return {"agent": self.name, "task": task, "tier": "offensive", 
                "status": "completed", "findings": findings}