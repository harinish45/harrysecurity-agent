# Extension Guide

## Overview

NEXUS-STRIKE is designed for extensibility. You can add custom tools, agents, LLM providers, and guardrails without modifying core code.

## Adding a Custom Tool

1. Create a new Python file in the appropriate domain directory under `nexus/tools/<domain>/`
2. Implement a `run(target: str, **kwargs) -> dict` function
3. Register the tool with `tool_registry.register()`

```python
# nexus/tools/webapp/my_tool.py
from nexus.foundation.schema import Finding, STATUS_COMPLETED, tool_result
from nexus.tools.registry import tool_registry

def run(target: str, **kwargs) -> dict:
    findings = []
    # Your tool logic here
    findings.append(Finding(
        title="My finding",
        severity="medium",
        affected_asset=target,
        evidence="Evidence string",
        remediation="How to fix",
        tool="webapp.my_tool",
    ))
    return tool_result("webapp.my_tool", target, findings=findings)

tool_registry.register("webapp.my_tool", run, metadata={
    "name": "webapp.my_tool",
    "domain": "webapp",
    "status": "completed",
    "description": "My custom tool",
})
```

## Adding a Custom Agent

1. Create a new file in the appropriate tier under `nexus/agents/<tier>/`
2. Extend `BaseAgent` and implement `async def run()`
3. Register in `nexus/agents/agent_registry.py`

```python
from nexus.agents.base_agent import BaseAgent
from nexus.tools.registry import tool_registry

class MyAgent(BaseAgent):
    name = "my_agent"
    description = "My custom agent"

    async def run(self, task: str, **kwargs) -> dict:
        target = kwargs.get("target", "")
        findings = []
        tool_fn = tool_registry.get("webapp.my_tool")
        result = tool_fn(target=target)
        if result.get("findings"):
            findings.extend(result["findings"])
        return {"agent": self.name, "task": task, "status": "completed", "findings": findings}
```

Then add to `agent_registry.py`:
```python
"my_agent": "nexus.agents.offensive.my_agent.MyAgent",
```

## Adding an LLM Provider

1. Create a provider file in `nexus/intelligence/llm/providers/`
2. Implement the provider interface
3. Add configuration in `nexus/foundation/config.py`
4. Register in `nexus/intelligence/llm/router.py`

## Adding a Guardrail

1. Create a guardrail file in `nexus/foundation/guardrails/`
2. Implement a class with a `validate()` classmethod
3. Add to `nexus/foundation/guardrails/__init__.py`
4. Wire into `nexus/tools/executor.py`

## Plugin Architecture

Tools and agents auto-discover via the registry pattern. No plugin manifest or configuration file is needed — just import and register.