"""Turns a bare technical finding into a business-impact statement.

"SQLi found" and "SQLi on the payments service" carry very different
priority in triage. This agent annotates each finding with a
``business_impact`` string using whatever asset-naming and engagement
context is available — a keyword heuristic, not a real data-flow analysis,
so it's conservative about how confidently it phrases the result.
"""
from __future__ import annotations

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result

_IMPACT_ZONES = (
    ("payment", "PCI-adjacent — cardholder/payment data exposure risk"),
    ("billing", "PCI-adjacent — cardholder/payment data exposure risk"),
    ("auth", "Identity/access-adjacent — credential or session compromise risk"),
    ("login", "Identity/access-adjacent — credential or session compromise risk"),
    ("sso", "Identity/access-adjacent — credential or session compromise risk"),
    ("admin", "Privileged-interface exposure — elevated blast radius if compromised"),
    ("user", "Customer PII-adjacent — personal data exposure risk"),
    ("customer", "Customer PII-adjacent — personal data exposure risk"),
    ("db", "Data-tier exposure — potential for bulk data access"),
    ("database", "Data-tier exposure — potential for bulk data access"),
    ("internal", "Internal-only asset — lower external exposure, high lateral-movement value if reached"),
    ("prod", "Production asset — direct customer-facing impact if exploited"),
)

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class BlastRadiusAgent(BaseAgent):
    name = "blast_radius_agent"
    description = "orchestrator agent that annotates findings with a business-impact statement"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        findings = kwargs.get("findings", []) or []
        engagement = kwargs.get("engagement") or {}
        if not findings:
            return tool_result(self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                                summary="No findings to assess business impact for")

        annotated = []
        for f in findings:
            f = dict(f)
            f["business_impact"] = self._impact_for(f, engagement)
            annotated.append(f)

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Business-impact annotation applied to {len(annotated)} finding(s)",
            metadata={"annotated_findings": annotated},
        )

    def _impact_for(self, finding: dict, engagement: dict) -> str:
        asset = str(finding.get("affected_asset", "")).lower()
        title = str(finding.get("title", "")).lower()
        haystack = f"{asset} {title}"

        for keyword, statement in _IMPACT_ZONES:
            if keyword in haystack:
                return statement

        client = engagement.get("client")
        severity = finding.get("severity", "info")
        weight = _SEVERITY_WEIGHT.get(severity, 0)
        if weight >= 3:
            base = "Externally reachable, no asset-tier signal available"
        else:
            base = "No specific business-impact signal identified from asset naming"
        return f"{base}{f' (client: {client})' if client else ''}"
