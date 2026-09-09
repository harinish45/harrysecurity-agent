from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, tool_result

class NetworkAgent(BaseAgent):
    name = "network_agent"
    description = "Network assessment agent that performs port scanning, service detection, and banner grabbing"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []

        # Run network tools from the registry
        for tool_name in ["network.port_scan", "network.banner_grab",
                          "network.host_discovery", "network.firewall_detect"]:
            try:
                result = tool_registry.run(tool_name, target=target)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{tool_name} skipped: {e}", "severity": "low", "confidence": "medium"})

        if not findings:
            # Fallback: basic port scan
            import socket
            import concurrent.futures
            common_ports = [22, 80, 443, 8080, 3306, 3389, 5432, 6379]
            def probe(port):
                try:
                    with socket.create_connection((target, port), timeout=1):
                        return port
                except OSError:
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                results = list(ex.map(probe, common_ports))
            open_ports = sorted(p for p in results if p is not None)
            if open_ports:
                findings.append({
                    "title": f"Open ports on {target}: {open_ports}", "severity": "medium", "confidence": "certain",
                    "affected_asset": target,
                })
            else:
                findings.append({
                    "title": f"No open ports found on {target} among {len(common_ports)} common ports",
                    "severity": "info", "confidence": "certain", "affected_asset": target,
                })

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Network assessment on {target}: {len(findings)} finding(s)",
        )