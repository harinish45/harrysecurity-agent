"""Builds a small attack-progression graph from findings collected so far and
recommends which domains to investigate next — a real (if modest) graph
model over static domain-adjacency rules, in the same spirit as
nexus.advanced.threat_modeling but scoped to "what should the mission look at
next" rather than full path prediction."""
from __future__ import annotations

import networkx as nx

# Which domains a finding in one domain typically motivates investigating next.
_NEXT_DOMAIN: dict[str, list[str]] = {
    "reconnaissance": ["network", "webapp", "cloud"],
    "network": ["vuln_assessment", "active_directory"],
    "webapp": ["vuln_assessment", "appsec"],
    "vuln_assessment": ["exploit", "compliance"],
    "cloud": ["vuln_assessment", "compliance"],
    "active_directory": ["exploit"],
    "malware": ["forensics", "reverse_engineering"],
    "wireless": ["network"],
}

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class AttackChain:
    @staticmethod
    def build(findings: list[dict]) -> nx.DiGraph:
        graph = nx.DiGraph()
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            tool = finding.get("tool") or ""
            domain = tool.split(".", 1)[0] if "." in tool else "reconnaissance"
            weight = _SEVERITY_WEIGHT.get(str(finding.get("severity", "info")).lower(), 0)
            prior = graph.nodes[domain]["weight"] if domain in graph.nodes else 0
            graph.add_node(domain, weight=prior + weight)
            for nxt in _NEXT_DOMAIN.get(domain, []):
                graph.add_edge(domain, nxt)
        return graph

    @staticmethod
    def recommend_next(findings: list[dict], limit: int = 3) -> list[str]:
        graph = AttackChain.build(findings)
        if graph.number_of_nodes() == 0:
            return ["reconnaissance"]

        scored = nx.pagerank(graph) if graph.number_of_edges() else {n: 1.0 for n in graph.nodes}

        candidates: dict[str, float] = {}
        for src, dst in graph.edges():
            src_weight = graph.nodes[src].get("weight", 0)
            candidates[dst] = max(candidates.get(dst, 0.0), src_weight + scored.get(dst, 0.0))

        if not candidates:
            return sorted(graph.nodes)[:limit]
        return [domain for domain, _ in sorted(candidates.items(), key=lambda kv: -kv[1])][:limit]
