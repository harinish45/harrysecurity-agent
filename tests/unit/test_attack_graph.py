import pytest

from nexus.analysis.graph import AttackGraph, GraphEdge, GraphNode


def test_attack_graph_returns_high_confidence_shortest_explanation_first():
    graph = AttackGraph()
    for node_id in ("internet", "web", "admin"):
        graph.add_node(GraphNode(node_id, "asset", node_id))
    graph.add_edge(GraphEdge("internet", "web", "reaches", 0.95))
    graph.add_edge(GraphEdge("web", "admin", "exposes", 0.9))
    graph.add_edge(GraphEdge("internet", "admin", "reaches", 0.5))

    paths = graph.find_paths("internet", "admin")
    assert len(paths) == 2
    assert paths[0].nodes == ("internet", "web", "admin")
    assert paths[0].score > paths[1].score


def test_graph_rejects_edges_to_unknown_nodes_and_invalid_confidence():
    graph = AttackGraph()
    graph.add_node(GraphNode("a", "asset", "A"))
    with pytest.raises(ValueError):
        graph.add_edge(GraphEdge("a", "missing", "reaches"))
    with pytest.raises(ValueError):
        GraphEdge("a", "a", "loop", 1.1)
