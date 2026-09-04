from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

class WebappAgent(BaseAgent):
    name = "webapp_agent"
    description = "Web application assessment agent that tests for SQLi, XSS, LFI, CMDi, SSRF, and directory enumeration"

    async def run(self, task: str, **kwargs) -> dict:
        target = kwargs.get("target", "")
        findings = []
        
        # Run webapp tools from the registry
        for tool_name in ["webapp.sqli", "webapp.xss", "webapp.lfi", 
                          "webapp.cmdi", "webapp.ssrf", "webapp.dir_enum"]:
            try:
                result = tool_registry.run(tool_name, target=target)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except (KeyError, Exception) as e:
                findings.append(f"[{tool_name}] skipped: {e}")
        
        if not findings:
            # Fallback: basic HTTP fingerprint
            import urllib.request
            import ssl
            url = target if "://" in target else f"http://{target}"
            try:
                ctx = get_ssl_context(url, allow_insecure=True)
                req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                findings.append(f"HTTP {resp.status}: Server={resp.headers.get('Server', 'unknown')}")
            except Exception as e:
                findings.append(f"HTTP check failed: {e}")

        return {"agent": self.name, "task": task, "tier": "offensive", 
                "status": "completed", "findings": findings}