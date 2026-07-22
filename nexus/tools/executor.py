from nexus.tools.registry import tool_registry

class ToolExecutor:
    def run(self, tool_name: str, target: str, **kwargs) -> dict:
        tool = tool_registry.get(tool_name)
        return tool(target=target, **kwargs)
