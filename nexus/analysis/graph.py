"""Deterministic attack-path graph primitives.

The graph is intentionally an analysis layer: it does not execute exploits. It
turns authorized observations into explainable relationships that planners and
reports can consume without inventing evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: str
    label: str
    asset: str = ""
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    confidence: float = 1.0
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("edge confidence must be between 0 and 1")


@dataclass(frozen=True)
class PathResult:
    nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]
    score: float


class AttackGraph:
    """Small in-memory directed graph with deterministic path analysis."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    @property
    def nodes(self) -> tuple[GraphNode, ...]:
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[GraphEdge, ...]:
        return tuple(self._edges)

    def add_node(self, node: GraphNode) -> None:
        existing = self._nodes.get(node.node_id)
        if existing and existing != node:
            raise ValueError(f"node already exists with different content: {node.node_id}")
        self._nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source not in self._nodes or edge.target not in self._nodes:
            raise ValueError("edges may only reference existing nodes")
        if edge.source == edge.target:
            raise ValueError("self-referential attack edges are not allowed")
        if edge not in self._edges:
            self._edges.append(edge)

    def outgoing(self, node_id: str) -> tuple[GraphEdge, ...]:
        return tuple(edge for edge in self._edges if edge.source == node_id)

    def find_paths(self, source: str, target: str, *, max_depth: int = 8) -> tuple[PathResult, ...]:
        if source not in self._nodes or target not in self._nodes:
            return ()
        if max_depth < 1:
            raise ValueError("max_depth must be positive")

        results: list[PathResult] = []

        def walk(node: str, nodes: tuple[str, ...], edges: tuple[GraphEdge, ...]) -> None:
            if len(edges) > max_depth:
                return
            if node == target:
                # Higher-confidence paths score higher while longer paths are
                # mildly penalized to keep explanations concise.
                confidence = 1.0
                for edge in edges:
                    confidence *= edge.confidence
                score = confidence / max(1, len(edges))
                results.append(PathResult(nodes, edges, score))
                return
            for edge in self.outgoing(node):
                if edge.target in nodes:
                    continue
                walk(edge.target, nodes + (edge.target,), edges + (edge,))

        walk(source, (source,), ())
        return tuple(sorted(results, key=lambda result: (-result.score, len(result.edges), result.nodes)))

    def to_dict(self) -> dict[str, list[dict[str, object]]]:
        return {
            "nodes": [
                {"node_id": n.node_id, "kind": n.kind, "label": n.label,
                 "asset": n.asset, "attributes": n.attributes}
                for n in self.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target, "relation": e.relation,
                 "confidence": e.confidence, "evidence_ids": list(e.evidence_ids)}
                for e in self.edges
            ],
        }

    @classmethod
    def from_pairs(cls, nodes: Iterable[GraphNode], edges: Iterable[GraphEdge]) -> "AttackGraph":
        graph = cls()
        for node in nodes:
            graph.add_node(node)
        for edge in edges:
            graph.add_edge(edge)
        return graph
