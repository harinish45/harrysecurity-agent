"""Predictive Threat Modeling — graph-based attack path prediction.

This is a REAL graph algorithm over a findings-derived asset topology, NOT a
trained machine-learning model. There is no historical attack-path training
data available to NEXUS-STRIKE (or to most single-organization security
tools) to train anything on, so a claim of "ML-based prediction" here would
be decorative rather than real. Instead this module:

  1. Builds the same kind of asset-relationship graph
     ``nexus.reporting.visualizations.attack_graph_viz.AttackGraphViz``
     builds: nodes are distinct ``affected_asset`` values, and an edge
     connects two assets when findings against them share a tool "domain"
     prefix (``tool.split(".")[0]``) — "touched by the same class of
     tooling", not a claim about real network reachability. The graph
     construction is intentionally re-implemented here (not imported) to
     keep this module independent of the reporting package while following
     the exact same approach; see that file for the original.

  2. Scores each node's "attacker interest" as a weighted combination of:
       a. ``networkx.pagerank`` centrality — how structurally central the
          asset is (a well-connected asset is a better pivot point).
       b. a severity-weighted SUM (not average — an asset with many issues
          should outrank one with a single low-severity issue) of the
          findings tied to that asset: critical=4, high=3, medium=2, low=1,
          info=0.
       c. a small, explicit, documented rule bonus (see ``_rule_bonus``) —
          at most two rules, each with a one-line rationale, kept simple and
          auditable rather than a black box.
     Both (a) and (b) are normalized to [0, 1] by dividing by their max
     across the graph before being averaged 50/50; the rule bonus is then
     added on top unnormalized (so it can push a node's score above 1 —
     that is intentional, it marks "this node matters for a documented,
     specific reason beyond generic centrality/severity").

  3. If ``critical_assets`` is given, finds the shortest path (by hop count,
     via ``nx.shortest_path`` on the directed graph as built) from every
     other reachable node to each critical asset, and ranks those paths by
     the summed risk score of the nodes on the path. If a node has no
     directed path to a given critical asset (edges are added in a single,
     insertion-order-dependent direction per pair — see step 1 — so this is
     common, not a bug), that pair is simply omitted from the results.
     Without ``critical_assets``, ``predict_attack_paths`` instead returns
     every node ranked by its own score as a single-node "path" — a general
     risk ranking of entry points rather than a route to one target.

What this does NOT do: it does not simulate exploitation, does not weight
edges by actual network reachability or firewall state (edges are the same
"same tooling domain" heuristic as ``AttackGraphViz`` — not a routability
claim), and does not learn or adapt from outcomes over time. On empty or
graph-less input it returns ``[]`` rather than raising.
"""
from __future__ import annotations

from typing import Any, Optional

import networkx as nx

# Rationale: a coarse but explainable per-finding severity contribution to
# an asset's aggregate risk. Summed (not averaged) across all findings on
# that asset — see module docstring.
_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Rule 1 keyword sets — title-based, deliberately simple substring checks.
_AUTH_KEYWORDS = ("auth", "login", "credential", "password", "session", "token")
_OPEN_SERVICE_KEYWORDS = ("open port", "port open", "service detected", "listening", "exposed service")

# Rule 1 bonus: an asset with both an auth-flavoured finding and a separate
# open-port/service finding is a materially easier compromise chain than
# either alone (a discoverable listener gives an attacker somewhere to
# actually point the exposed auth surface at).
_RULE1_BONUS = 1.5

# Rule 2 bonus: two or more independently-critical findings on one asset
# signal a broadly, not narrowly, vulnerable asset — a bigger attacker
# payoff than a single critical issue.
_RULE2_BONUS = 1.0
_RULE2_MIN_CRITICALS = 2


class ThreatModeler:
    """Graph-based, explainable attack-path predictor (see module docstring)."""

    def predict_attack_paths(
        self,
        findings: list[dict[str, Any]],
        *,
        critical_assets: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        if not findings:
            return []

        graph, findings_by_asset = self._build_graph(findings)
        if graph.number_of_nodes() == 0:
            return []

        scores = self._node_scores(graph, findings_by_asset)

        if not critical_assets:
            ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
            return [
                {
                    "path": [node],
                    "risk_score": score,
                    "rationale": (
                        f"Standalone risk ranking for '{node}' (no critical_assets "
                        "supplied): combined graph centrality, severity-weighted "
                        "finding score, and rule bonuses."
                    ),
                }
                for node, score in ranked
            ]

        results: list[dict[str, Any]] = []
        for critical_asset in critical_assets:
            if critical_asset not in graph:
                continue
            for node in graph.nodes():
                if node == critical_asset:
                    continue
                try:
                    path = nx.shortest_path(graph, source=node, target=critical_asset)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                risk = sum(scores.get(n, 0.0) for n in path)
                results.append({
                    "path": path,
                    "risk_score": round(risk, 4),
                    "rationale": (
                        f"{len(path) - 1}-hop path from '{node}' to critical asset "
                        f"'{critical_asset}' via shared-tool-domain edges; risk_score "
                        "is the sum of each hop's centrality + severity + rule score."
                    ),
                })

        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    # -- construction --------------------------------------------------

    def _build_graph(
        self, findings: list[dict[str, Any]]
    ) -> tuple["nx.DiGraph", dict[str, list[dict[str, Any]]]]:
        graph: nx.DiGraph = nx.DiGraph()
        asset_domains: dict[str, set[str]] = {}
        findings_by_asset: dict[str, list[dict[str, Any]]] = {}

        for f in findings:
            asset = str(f.get("affected_asset") or "").strip()
            if not asset:
                continue
            graph.add_node(asset)
            findings_by_asset.setdefault(asset, []).append(f)
            tool = str(f.get("tool") or "")
            domain = tool.split(".")[0] if tool else ""
            if domain:
                asset_domains.setdefault(asset, set()).add(domain)

        assets = list(asset_domains.keys())
        for i, a in enumerate(assets):
            for b in assets[i + 1:]:
                if asset_domains[a] & asset_domains[b]:
                    graph.add_edge(a, b)

        return graph, findings_by_asset

    # -- scoring ----------------------------------------------------------

    def _node_scores(
        self, graph: "nx.DiGraph", findings_by_asset: dict[str, list[dict[str, Any]]]
    ) -> dict[str, float]:
        if graph.number_of_nodes() == 1:
            pagerank = {next(iter(graph.nodes())): 1.0}
        else:
            try:
                pagerank = nx.pagerank(graph)
            except Exception:
                # Degenerate (e.g. edgeless) graphs: uniform centrality.
                n = graph.number_of_nodes() or 1
                pagerank = {node: 1.0 / n for node in graph.nodes()}
        max_pagerank = max(pagerank.values()) if pagerank else 1.0
        max_pagerank = max_pagerank or 1.0

        severity_sums = {
            asset: sum(
                _SEVERITY_SCORE.get(str(f.get("severity", "info")).lower(), 0)
                for f in fs
            )
            for asset, fs in findings_by_asset.items()
        }
        max_severity = max(severity_sums.values()) if severity_sums else 0

        scores: dict[str, float] = {}
        for node in graph.nodes():
            pr_norm = pagerank.get(node, 0.0) / max_pagerank
            sev_norm = (severity_sums.get(node, 0) / max_severity) if max_severity else 0.0
            bonus = self._rule_bonus(findings_by_asset.get(node, []))
            scores[node] = round(0.5 * pr_norm + 0.5 * sev_norm + bonus, 4)
        return scores

    @staticmethod
    def _rule_bonus(findings: list[dict[str, Any]]) -> float:
        bonus = 0.0
        titles = [str(f.get("title", "")).lower() for f in findings]

        has_auth = any(any(k in t for k in _AUTH_KEYWORDS) for t in titles)
        has_open_service = any(any(k in t for k in _OPEN_SERVICE_KEYWORDS) for t in titles)
        if has_auth and has_open_service:
            bonus += _RULE1_BONUS  # Rule 1 — see module docstring

        critical_count = sum(
            1 for f in findings if str(f.get("severity", "")).lower() == "critical"
        )
        if critical_count >= _RULE2_MIN_CRITICALS:
            bonus += _RULE2_BONUS  # Rule 2 — see module docstring

        return bonus
