"""Cross-domain attack-chain graph search.

Per the Dec-2025 ARTEMIS study (Stanford/CMU/Gray Swan, live 8,000-host
network), the gap between the best autonomous pentest agent and top human
testers wasn't raw tool execution — it was creative multi-step chaining and
business-logic bugs. A flat findings list can't surface "this credential
unlocks that host" on its own; a graph search over what each finding
plausibly *unlocks* can. This agent builds that graph deterministically
(same asset-adjacency heuristic `AttackGraphViz` already uses for the SVG
render, plus a credential/access keyword edge) and emits any 2+-hop chain it
finds as its own synthetic finding, so chained risk isn't buried in a list
sorted by individual-finding severity alone.
"""
from __future__ import annotations

from typing import Any

import networkx as nx

from nexus.agents.base_agent import BaseAgent
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_NO_FINDINGS, tool_result

_UNLOCK_KEYWORDS = (
    "credential", "password", "token", "api key", "api_key", "secret",
    "admin", "privilege", "session", "cookie", "ssh key", "access key",
)
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


class AttackChainAgent(BaseAgent):
    name = "attack_chain_agent"
    description = "orchestrator agent that graph-searches findings for cross-asset attack chains"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        findings = kwargs.get("findings", []) or []
        if len(findings) < 2:
            return tool_result(self.name, target or "unknown", status=STATUS_NO_FINDINGS,
                                summary="Not enough findings to search for chains")

        graph, by_asset = self._build_graph(findings)
        chains = self._find_chains(graph, by_asset)

        chain_findings = []
        for i, chain in enumerate(chains, 1):
            worst = min(
                (self._severity_index(by_asset[a]) for a in chain if a in by_asset),
                default=4,
            )
            elevated = _SEVERITY_ORDER[max(0, worst - 1)]
            chain_findings.append({
                "id": f"CHAIN-{i:03d}",
                "title": f"Attack chain: {' -> '.join(chain)}",
                "severity": elevated,
                "confidence": "medium",
                "affected_asset": chain[0],
                "evidence": f"Composed from {len(chain)} linked findings across assets: {', '.join(chain)}",
                "remediation": "Break the chain at its weakest link — prioritize the earliest hop.",
                "chain_assets": chain,
                "kind": "synthetic_chain",
            })

        return tool_result(
            self.name, target or "unknown",
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"Chain search over {len(findings)} finding(s) across {graph.number_of_nodes()} asset(s): "
                    f"{len(chain_findings)} chain(s) found",
            metadata={"chains": chain_findings},
        )

    @staticmethod
    def _severity_index(findings_for_asset: list[dict]) -> int:
        best = 4
        for f in findings_for_asset:
            sev = f.get("severity", "info")
            if sev in _SEVERITY_ORDER:
                best = min(best, _SEVERITY_ORDER.index(sev))
        return best

    def _build_graph(self, findings: list[dict[str, Any]]) -> tuple["nx.DiGraph", dict[str, list[dict]]]:
        graph: nx.DiGraph = nx.DiGraph()
        by_asset: dict[str, list[dict]] = {}
        asset_domains: dict[str, set[str]] = {}
        unlock_assets: set[str] = set()

        for f in findings:
            asset = str(f.get("affected_asset") or "").strip()
            if not asset:
                continue
            graph.add_node(asset)
            by_asset.setdefault(asset, []).append(f)
            tool = str(f.get("tool") or "")
            if tool:
                asset_domains.setdefault(asset, set()).add(tool.split(".")[0])
            title_evidence = f"{f.get('title', '')} {f.get('evidence', '')}".lower()
            if any(kw in title_evidence for kw in _UNLOCK_KEYWORDS):
                unlock_assets.add(asset)

        assets = list(by_asset.keys())
        for a in assets:
            for b in assets:
                if a == b:
                    continue
                # An "unlock"-flavoured finding on `a` plausibly leads to `b`
                # when they were touched by the same class of tooling —
                # directed edge, a -> b.
                if a in unlock_assets and (asset_domains.get(a, set()) & asset_domains.get(b, set())):
                    graph.add_edge(a, b)

        return graph, by_asset

    @staticmethod
    def _find_chains(graph: "nx.DiGraph", by_asset: dict[str, list[dict]], max_chains: int = 10) -> list[list[str]]:
        chains: list[list[str]] = []
        sources = [n for n in graph.nodes() if graph.out_degree(n) > 0]
        for source in sources:
            for target_node in graph.nodes():
                if target_node == source:
                    continue
                try:
                    for path in nx.all_simple_paths(graph, source, target_node, cutoff=4):
                        if len(path) >= 2 and path not in chains:
                            chains.append(path)
                        if len(chains) >= max_chains:
                            return chains
                except nx.NodeNotFound:
                    continue
        return chains
