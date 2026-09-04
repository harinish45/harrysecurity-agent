from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry

class NetworkAgent(BaseAgent):
    name = "network_agent"
    description = "Network assessment agent that performs port scanning, service detection, and banner grabbing"

    async def run(self, task: str, **kwargs) -> dict:
        target = kwargs.get("target", "")
        findings = []
        
        # Run network tools from the registry
        for tool_name in ["network.port_scan", "network.banner_grab", 
                          "network.host_discovery", "network.firewall_detect"]:
            try:
                result = tool_registry.run(tool_name, target=target)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except (KeyError, Exception) as e:
                findings.append(f"[{tool_name}] skipped: {e}")
        
        if not findings:
            # Fallback: basic port scan
            import socket
            import concurrent.futures
            common_ports = [22, 80, 443, 8080, 3306, 3389, 5432, 6379]
            def probe(port):
                try:
                    with socket.create_connection((target, port), timeout=1):
                        return port
                except:
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                results = list(ex.map(probe, common_ports))
            open_ports = sorted(p for p in results if p is not None)
            if open_ports:
                findings.append(f"Open ports on {target}: {open_ports}")
            else:
                findings.append(f"No open ports found on {target} among {len(common_ports)} common ports")

        return {"agent": self.name, "task": task, "tier": "offensive", 
                "status": "completed", "findings": findings}