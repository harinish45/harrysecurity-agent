from nexus.orchestration.agent_patterns import AgentRole, PlanningPattern
from nexus.intelligence.memory.store import MemoryItem, MemoryStore


def test_planning_pattern_creates_isolated_specialist_chain():
    delegations = PlanningPattern().decompose("m1", "t1", "map attack surface")
    assert [item.role for item in delegations] == [
        AgentRole.RESEARCHER,
        AgentRole.EXECUTOR,
        AgentRole.VALIDATOR,
        AgentRole.REFINER,
    ]
    assert all(item.fresh_context for item in delegations)


def test_memory_store_round_trip_and_tag_search(tmp_path):
    store = MemoryStore(tmp_path / "memory.json")
    store.put(MemoryItem("finding:1", "ssh exposed", "m1", ("network", "finding")))
    store.put(MemoryItem("note:1", "review later", "m1", ("note",)))

    assert store.get("finding:1").value == "ssh exposed"
    assert [item.key for item in store.search(("finding",))] == ["finding:1"]
