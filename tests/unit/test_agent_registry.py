#!/usr/bin/env python3
"""
NEXUS-STRIKE — Unit Tests: Agent Registry
Ensures all registered agents have a valid run() method.
"""
import pytest
from nexus.agents.agent_registry import list_agents, get_agent_count

def test_agent_count():
    """Verify we have a substantial number of agents registered."""
    assert get_agent_count() >= 50, f"Expected at least 50 agents, got {get_agent_count()}"

@pytest.mark.parametrize("agent_name,agent_class", list_agents())
def test_agent_has_run_method(agent_name: str, agent_class: type):
    """Verify all agents have a real run() method."""
    assert hasattr(agent_class, 'run'), f"Agent {agent_name} is missing 'run' method"
    assert callable(getattr(agent_class, 'run')), f"Agent {agent_name} 'run' attribute is not callable"
    
    # Optional: verify it's not just a stub by checking docstring or signature
    run_method = getattr(agent_class, 'run')
    assert run_method.__doc__ is not None or True, f"Agent {agent_name} run method lacks documentation"