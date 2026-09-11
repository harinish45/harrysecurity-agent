import pytest

from nexus.orchestration.scheduler.dependency_graph import DependencyGraph, GraphError


def test_independent_tasks_form_a_single_batch():
    g = DependencyGraph()
    g.add_task("A")
    g.add_task("B")
    g.add_task("C")
    assert g.batches() == [["A", "B", "C"]]


def test_linear_chain_forms_one_batch_per_task():
    g = DependencyGraph()
    g.add_task("A")
    g.add_task("B", depends_on=["A"])
    g.add_task("C", depends_on=["B"])
    assert g.batches() == [["A"], ["B"], ["C"]]


def test_diamond_dependency_batches_the_parallel_branch():
    g = DependencyGraph()
    g.add_task("A")
    g.add_task("B", depends_on=["A"])
    g.add_task("C", depends_on=["A"])
    g.add_task("D", depends_on=["B", "C"])
    assert g.batches() == [["A"], ["B", "C"], ["D"]]


def test_cycle_raises_graph_error():
    g = DependencyGraph()
    g.add_task("A", depends_on=["B"])
    g.add_task("B", depends_on=["A"])
    with pytest.raises(GraphError):
        g.batches()


def test_unknown_dependency_raises_graph_error():
    g = DependencyGraph()
    g.add_task("A", depends_on=["ghost"])
    with pytest.raises(GraphError):
        g.batches()


def test_empty_graph_has_no_batches():
    assert DependencyGraph().batches() == []
