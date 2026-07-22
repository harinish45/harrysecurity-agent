from nexus.tools.registry import tool_registry

def test_registry():
    assert tool_registry.count > 0
    assert 'reconnaissance.subdomain_enum' in tool_registry.list_tools()
