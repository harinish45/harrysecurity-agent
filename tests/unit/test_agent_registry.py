from nexus.agents.agent_registry import list_agents, get_agent_count

def test_agents():
    assert get_agent_count() > 10
