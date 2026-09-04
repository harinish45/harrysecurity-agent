from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result


class SearcherAgent(BaseAgent):
    name = "searcher_agent"
    description = "support agent for searching — gathers intelligence from multiple sources and search engines"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        if not target:
            return tool_result(self.name, target or "unknown", status=STATUS_FAILED, error="No target specified")

        findings = []
        tools_used = []
        sources = []

        recon_tools = [
            ("reconnaissance.subdomain_enum", "subdomain enumeration"),
            ("reconnaissance.dns_recon", "DNS reconnaissance"),
            ("reconnaissance.github_recon", "GitHub reconnaissance"),
            ("reconnaissance.shodan_search", "Shodan search"),
            ("threat_intel.threat_feeds", "threat intelligence feeds"),
        ]

        for tool_name, source_name in recon_tools:
            try:
                result = tool_registry.run(tool_name, target=target)
                tools_used.append(tool_name)
                sources.append(source_name)
                if result.get("findings"):
                    findings.extend(result["findings"])
            except Exception as e:
                findings.append({"title": f"{source_name} error: {e}", "severity": "low", "confidence": "medium"})

        unique_findings = []
        seen_titles = set()
        for f in findings:
            title = f.get("title", "")
            if title and title not in seen_titles:
                seen_titles.add(title)
                unique_findings.append(f)

        return tool_result(
            self.name, target,
            status=STATUS_COMPLETED,
            findings=unique_findings,
            summary=f"Intelligence gathered from {len(sources)} sources, {len(unique_findings)} unique findings",
            metadata={
                "sources": sources,
                "tools_used": tools_used,
                "total_raw_findings": len(findings),
                "total_unique_findings": len(unique_findings),
                "deduplication_applied": True,
            },
        )
