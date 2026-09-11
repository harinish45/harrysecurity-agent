"""Attack-graph visualization — hand-rolled inline SVG, no graphics stack.

Nodes are distinct ``affected_asset`` values across a set of findings; an
edge connects two assets when findings against them share a tool "domain"
prefix (``tool.split(".")[0]``) — a simple, defensible heuristic meaning
"these assets were touched by the same class of tooling", not a claim about
actual network reachability or lateral-movement paths.
"""
from __future__ import annotations

from typing import Any

import networkx as nx

SVG_WIDTH = 800
SVG_HEIGHT = 500
_MARGIN = 60


class AttackGraphViz:
    """Render a findings-derived asset relationship graph as an SVG string."""

    def render(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return self._empty_svg("No data")

        graph = self._build_graph(findings)
        if graph.number_of_nodes() == 0:
            return self._empty_svg("No data")

        if graph.number_of_nodes() == 1:
            # pagerank/spring_layout are happy with a single node, but keep
            # this explicit for clarity/determinism.
            scores = {next(iter(graph.nodes())): 1.0}
        else:
            try:
                scores = nx.pagerank(graph)
            except Exception:
                # Edgeless (or otherwise degenerate) graphs: uniform scores.
                n = graph.number_of_nodes() or 1
                scores = {node: 1.0 / n for node in graph.nodes()}

        positions = nx.spring_layout(graph, seed=42)
        return self._to_svg(graph, positions, scores)

    # -- construction ------------------------------------------------------

    def _build_graph(self, findings: list[dict[str, Any]]) -> "nx.DiGraph":
        graph: nx.DiGraph = nx.DiGraph()
        asset_domains: dict[str, set[str]] = {}

        for f in findings:
            asset = str(f.get("affected_asset") or "").strip()
            if not asset:
                continue
            graph.add_node(asset)
            tool = str(f.get("tool") or "")
            domain = tool.split(".")[0] if tool else ""
            if domain:
                asset_domains.setdefault(asset, set()).add(domain)

        assets = list(asset_domains.keys())
        for i, a in enumerate(assets):
            for b in assets[i + 1:]:
                if asset_domains[a] & asset_domains[b]:
                    graph.add_edge(a, b)

        return graph

    # -- rendering -----------------------------------------------------------

    def _to_svg(self, graph: "nx.DiGraph", positions: dict, scores: dict) -> str:
        xs = [p[0] for p in positions.values()]
        ys = [p[1] for p in positions.values()]
        x_min, x_max = min(xs), max(xs)
        y_min, y_max = min(ys), max(ys)
        x_span = (x_max - x_min) or 1.0
        y_span = (y_max - y_min) or 1.0

        def scaled(node: str) -> tuple[float, float]:
            x, y = positions[node]
            sx = _MARGIN + (x - x_min) / x_span * (SVG_WIDTH - 2 * _MARGIN)
            sy = _MARGIN + (y - y_min) / y_span * (SVG_HEIGHT - 2 * _MARGIN)
            return sx, sy

        max_score = max(scores.values()) or 1.0

        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
            f'role="img" aria-label="Attack graph">',
            f'<rect width="{SVG_WIDTH}" height="{SVG_HEIGHT}" fill="#0a0d14"/>',
        ]

        for a, b in graph.edges():
            ax, ay = scaled(a)
            bx, by = scaled(b)
            parts.append(
                f'<line x1="{ax:.1f}" y1="{ay:.1f}" x2="{bx:.1f}" y2="{by:.1f}" '
                f'stroke="#334155" stroke-width="1.5"/>'
            )

        for node in graph.nodes():
            x, y = scaled(node)
            importance = scores.get(node, 0.0) / max_score
            radius = 8 + importance * 18
            color = self._node_color(importance)
            label = node if len(node) <= 22 else node[:19] + "..."
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" fill="{color}" '
                f'fill-opacity="0.85" stroke="#0a0d14" stroke-width="1.5"/>'
            )
            parts.append(
                f'<text x="{x:.1f}" y="{y + radius + 12:.1f}" font-size="10" '
                f'fill="#e2e8f0" text-anchor="middle" font-family="monospace">{_esc(label)}</text>'
            )

        parts.append('</svg>')
        return "\n".join(parts)

    @staticmethod
    def _node_color(importance: float) -> str:
        if importance >= 0.66:
            return "#dc2626"
        if importance >= 0.33:
            return "#f97316"
        return "#3b82f6"

    @staticmethod
    def _empty_svg(message: str) -> str:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
            f'role="img" aria-label="Attack graph">'
            f'<rect width="{SVG_WIDTH}" height="{SVG_HEIGHT}" fill="#0a0d14"/>'
            f'<text x="{SVG_WIDTH / 2}" y="{SVG_HEIGHT / 2}" font-size="16" fill="#64748b" '
            f'text-anchor="middle" font-family="sans-serif">{_esc(message)}</text>'
            f'</svg>'
        )


def _esc(text: str) -> str:
    from html import escape
    return escape(str(text))
