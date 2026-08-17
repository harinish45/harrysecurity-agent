from nexus.platform.capabilities import CapabilityState, WorkflowMode, catalogue, feature_parity_matrix
from nexus.platform.workflows import TaskGraph, TaskState, workflows


def test_capability_catalogue_has_unified_workflow_and_agent_roles():
    assert catalogue.get("workflow.pentest") is not None
    assert catalogue.get("agent.supervisor") is not None
    assert catalogue.get("agent.api_security") is not None
    assert catalogue.get("agent.ai_security") is not None
    assert CapabilityState.REGISTERED in catalogue.get("workflow.pentest").states


def test_feature_parity_matrix_is_deterministic_and_machine_readable():
    matrix = feature_parity_matrix()
    assert matrix == feature_parity_matrix()
    assert len(matrix) >= 70
    assert {row["domain"] for row in matrix} >= {
        "workflow", "orchestration", "intelligence", "reporting", "enterprise"
    }
    assert all({"key", "title", "domain", "state", "implemented"}.issubset(row) for row in matrix)


def test_standard_workflow_is_dependency_ordered():
    workflow = workflows.get(WorkflowMode.PENTEST)
    graph = TaskGraph()
    for task in workflow.tasks:
        graph.add(task)
    assert graph.critical_path() == ["recon", "surface", "assessment", "correlate", "report"]
    assert [task.id for task in graph.ready()] == ["recon"]


def test_task_graph_rejects_cycles():
    graph = TaskGraph()
    graph.add(__import__("nexus.platform.workflows", fromlist=["WorkflowTask"]).WorkflowTask("a", "A", "agent.recon"))
    graph.tasks["a"] = graph.tasks["a"].__class__("a", "A", "agent.recon", depends_on=("b",), state=TaskState.PENDING)
    graph.tasks["b"] = graph.tasks["a"].__class__("b", "B", "agent.recon", depends_on=("a",), state=TaskState.PENDING)
    try:
        graph.critical_path()
    except ValueError as exc:
        assert "cycle" in str(exc)
    else:
        raise AssertionError("expected cycle detection")


def test_purple_team_has_explicit_retest_gate():
    workflow = workflows.get(WorkflowMode.PURPLE_TEAM)
    assert workflow.tasks[-1].id == "retest"
    assert workflow.tasks[-1].requires_approval is True
