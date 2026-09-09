from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context
from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, tool_result

class WebappAgent(BaseAgent):
    name = "webapp_agent"
    description = "Web application assessment agent that tests for SQLi, XSS, LFI, CMDi, SSRF, and directory enumeration"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []

        # Run webapp tools from the registry
        for tool_name in ["webapp.sqli", "webapp.xss", "webapp.lfi",
                          "webapp.cmdi", "webapp.ssrf", "webapp.dir_enum"]:
            try:
                result = tool_registry.run(tool_name, target=target)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{tool_name} skipped: {e}", "severity": "low", "confidence": "medium"})

        if not findings:
            # Fallback: basic HTTP fingerprint
            import urllib.request
            url = target if "://" in target else f"http://{target}"
            try:
                ctx = get_ssl_context(url, allow_insecure=True)
                req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
                resp = safe_urlopen(req, timeout=5, context=ctx)
                findings.append({
                    "title": f"HTTP {resp.status}: Server={resp.headers.get('Server', 'unknown')}",
                    "severity": "info", "confidence": "certain", "affected_asset": target,
                })
            except Exception as e:
                findings.append({"title": f"HTTP check failed: {e}", "severity": "low", "confidence": "medium"})

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=findings,
            summary=f"Web application assessment on {target}: {len(findings)} finding(s)",
        )