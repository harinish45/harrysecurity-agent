import pytest

from nexus.orchestration.flow.flow_controller import FlowController
from nexus.orchestration.flow.task_manager import TaskManager
from nexus.orchestration.scheduler.priority_queue import PriorityQueue


def test_priority_queue_drains_highest_priority_first():
    pq = PriorityQueue()
    pq.push("low-task", priority="low")
    pq.push("critical-task", priority="critical")
    pq.push("medium-task", priority="medium")
    assert pq.drain_sorted() == ["critical-task", "medium-task", "low-task"]


def test_task_manager_batches_a_diamond_shaped_plan():
    tasks = [
        {"id": "P1", "agent": "recon_agent", "depends_on": []},
        {"id": "P2", "agent": "network_agent", "depends_on": ["P1"]},
        {"id": "P3", "agent": "webapp_agent", "depends_on": ["P1"]},
        {"id": "P4", "agent": "vuln_analyst_agent", "depends_on": ["P2", "P3"]},
    ]
    batches = TaskManager.plan(tasks)
    assert [t["id"] for t in batches[0]] == ["P1"]
    assert sorted(t["id"] for t in batches[1]) == ["P2", "P3"]
    assert [t["id"] for t in batches[2]] == ["P4"]


def test_task_manager_assigns_ids_when_missing():
    batches = TaskManager.plan([{"agent": "recon_agent"}])
    assert batches[0][0]["id"] == "T1"


@pytest.mark.asyncio
async def test_flow_controller_dispatches_to_real_agents(monkeypatch):
    """End-to-end: FlowController must call the actual nexus.agents.* class
    named on each task, not silently no-op — this is the core fix for
    agents that were previously registered but never invoked."""
    calls = []

    async def fake_recon_run(self, task, **kwargs):
        calls.append(("recon_agent", task, kwargs.get("target")))
        return {"agent": "recon_agent", "status": "completed", "findings": [{"title": "found something", "severity": "low"}]}

    from nexus.agents.offensive.recon_agent import ReconAgent
    monkeypatch.setattr(ReconAgent, "run", fake_recon_run)

    controller = FlowController("test-mission", checkpoint=False)
    results = await controller.run([
        {"agent": "recon_agent", "task": "recon the target", "target": "127.0.0.1"},
    ])

    assert calls == [("recon_agent", "recon the target", "127.0.0.1")]
    assert results[0]["status"] == "completed"
    assert results[0]["findings"][0]["title"] == "found something"
    assert controller.strategy == "sequential"


@pytest.mark.asyncio
async def test_flow_controller_runs_independent_phases_as_one_batch(monkeypatch):
    seen_order = []

    async def fake_run(self, task, **kwargs):
        seen_order.append(self.name)
        return {"agent": self.name, "status": "completed", "findings": []}

    from nexus.agents.offensive.network_agent import NetworkAgent
    from nexus.agents.offensive.webapp_agent import WebappAgent
    monkeypatch.setattr(NetworkAgent, "run", fake_run)
    monkeypatch.setattr(WebappAgent, "run", fake_run)

    controller = FlowController("test-mission-parallel", checkpoint=False)
    await controller.run([
        {"id": "P1", "agent": "network_agent", "task": "scan", "target": "127.0.0.1", "depends_on": []},
        {"id": "P2", "agent": "webapp_agent", "task": "assess", "target": "127.0.0.1", "depends_on": []},
    ])

    assert controller.strategy == "parallel"
    assert sorted(seen_order) == ["network_agent", "webapp_agent"]
