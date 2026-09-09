#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec.threat_modeling
Domain: appsec
Real threat modeling built from prior scan findings: reuses
MitreMappingAgent's real ATT&CK keyword-technique table and
AttackChainAgent's real asset-adjacency graph search (both in
nexus/agents/orchestrator/) to tag supplied findings with techniques and
surface any multi-hop attack chains between the assets they touch.

Previously this ignored `target` and any supplied findings entirely and did
a bare DNS resolve + HTTP GET on "/" (byte-for-byte identical to 19 other
stub tools) — caught during this session's audit. Threat modeling is
inherently derived from *other* findings, not something observable by
probing a bare target with no prior data; when no `findings` are supplied,
this honestly reports STATUS_NO_FINDINGS instead of fabricating a model.
"""
from __future__ import annotations

from typing import Any

from nexus.agents.orchestrator.attack_chain_agent import AttackChainAgent
from nexus.agents.orchestrator.mitre_mapping_agent import MitreMappingAgent
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result
from nexus.tools.registry import tool_registry


def _as_dict(f: Any) -> dict:
    if isinstance(f, dict):
        return dict(f)
    if hasattr(f, "to_dict"):
        return f.to_dict()
    return dict(vars(f))


def run(target: str, findings: list[Any] | None = None, **kwargs: Any) -> dict:
    """Real threat model: ATT&CK-tags and chain-searches findings supplied via `findings=[...]`.

    Parameters
    ----------
    target : str
        The asset/engagement the supplied findings relate to (for labeling only).
    findings : list, optional
        Prior findings (dicts or Finding objects) from earlier tool runs.
    """
    tool_name = "appsec.threat_modeling"
    findings_in = findings if findings is not None else (kwargs.get("findings") or [])

    if not findings_in:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"Threat modeling requires prior scan findings (pass findings=[...] from an earlier "
                    f"assessment); none were supplied for {target}, so no synthetic threat model was built.",
        )

    mitre_agent = MitreMappingAgent()
    chain_agent = AttackChainAgent()

    annotated: list[dict] = []
    coverage: dict[str, int] = {}
    for raw in findings_in:
        fd = _as_dict(raw)
        techniques = mitre_agent._techniques_for(fd)
        fd["mitre_techniques"] = techniques
        for t in techniques:
            coverage[t["id"]] = coverage.get(t["id"], 0) + 1
        annotated.append(fd)

    graph, by_asset = chain_agent._build_graph(annotated)
    chains = chain_agent._find_chains(graph, by_asset)

    out_findings: list[Finding] = []
    for chain in chains:
        out_findings.append(Finding(
            title=f"Threat model attack chain: {' -> '.join(chain)}",
            severity="high",
            confidence="medium",
            affected_asset=chain[0],
            evidence=f"Composed via real AttackChainAgent graph search across {len(chain)} asset(s): "
                     f"{', '.join(chain)}",
            remediation="Break the chain at its weakest (earliest) link.",
            tool=tool_name,
            chain_assets=chain,
            kind="synthetic_chain",
        ))

    return tool_result(
        tool_name, target,
        status=STATUS_COMPLETED,
        findings=out_findings,
        summary=f"Real threat model built from {len(findings_in)} supplied finding(s) via "
                f"MitreMappingAgent/AttackChainAgent's real graph logic: {len(coverage)} distinct ATT&CK "
                f"technique(s) covered, {len(chains)} attack chain(s) found.",
        metadata={
            "technique_coverage": coverage,
            "annotated_findings": annotated,
            "chain_count": len(chains),
        },
    )


tool_registry.register("appsec.threat_modeling", run, metadata={
    "name": "appsec.threat_modeling",
    "domain": "appsec",
    "status": "completed",
    "description": "Real threat modeling: ATT&CK-tags and chain-searches supplied prior findings via "
                    "MitreMappingAgent/AttackChainAgent's real logic",
    "parameters": {
        "target": "The asset/engagement the supplied findings relate to (labeling only)",
        "findings": "Prior findings (list of dicts) from earlier tool runs to model",
    },
})
