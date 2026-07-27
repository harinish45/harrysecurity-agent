# Tool Development Guide

## Overview

All security tools in NEXUS-STRIKE follow a consistent contract. Each tool is a Python module with a `run()` function that accepts `target` and returns a standardized result dictionary.

## Tool Contract

Every tool must:

1. Be a Python file in the appropriate domain directory under `nexus/tools/<domain>/`
2. Export a `run(target: str, **kwargs) -> dict` function
3. Return results using `tool_result()` from `nexus.foundation.schema`
4. Use `Finding` dataclass for findings
5. Register with `tool_registry.register()`

## Minimal Tool Example

```python
# nexus/tools/webapp/example_tool.py
from nexus.foundation.schema import Finding, STATUS_COMPLETED, tool_result
from nexus.tools.registry import tool_registry

def run(target: str, **kwargs) -> dict:
    """Performs an example security check.
    
    Parameters
    ----------
    target : str
        The target URL, hostname, or IP address.
    timeout : int, optional
        Request timeout in seconds.
    """
    findings = []
    
    # Your security testing logic here
    # Use kwargs for optional parameters
    timeout = kwargs.get("timeout", 10)
    
    findings.append(Finding(
        title="Example finding title",
        severity="medium",  # critical, high, medium, low, info
        confidence="high",  # certain, high, medium, low, tentative
        affected_asset=target,
        evidence="Evidence that supports this finding",
        remediation="How to fix the issue",
        tool="webapp.example_tool",
        references=["CWE-79", "OWASP-A03"],
    ))
    
    return tool_result(
        "webapp.example_tool",
        target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary="Checks completed: 1 finding",
        metadata={"checked": True},
    )

# Register with the tool registry
tool_registry.register("webapp.example_tool", run, metadata={
    "name": "webapp.example_tool",
    "domain": "webapp",
    "status": "completed",
    "description": "Example security check tool",
    "parameters": {
        "target": "Target URL or hostname",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})
```

## Available Finding Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | str | Yes | Short human-readable title |
| `severity` | str | Yes | critical, high, medium, low, info |
| `confidence` | str | No | certain, high, medium, low, tentative |
| `affected_asset` | str | Yes | Host, URL, or component where issue exists |
| `evidence` | str | No | Machine-parseable evidence |
| `remediation` | str | No | Action for asset owner |
| `references` | list | No | CVE, CWE, OWASP identifiers |
| `tool` | str | Yes | Fully-qualified tool name |

## Available Status Values

| Constant | Value | When to Use |
|----------|-------|-------------|
| `STATUS_COMPLETED` | completed | Tool ran successfully (with or without findings) |
| `STATUS_NO_FINDINGS` | no_findings | Tool ran successfully, zero findings |
| `STATUS_FAILED` | failed | Tool encountered an error |
| `STATUS_UNAVAILABLE` | unavailable | Tool cannot run in this environment |
| `STATUS_OUT_OF_SCOPE` | out_of_scope | Target not covered by this tool |
| `STATUS_REQUIRES_CREDENTIALS` | requires_credentials | Tool needs API keys or credentials |

## Testing Your Tool

```python
# test_example_tool.py
from nexus.tools.webapp.example_tool import run

result = run(target="http://test-server.local")
print(f"Status: {result['status']}")
print(f"Findings: {len(result['findings'])}")
print(f"Summary: {result['summary']}")
```

## Best Practices

1. **Handle failures gracefully**: Never raise exceptions — catch them and return `STATUS_FAILED`
2. **Use timeouts**: Network tools should have configurable timeouts via `kwargs`
3. **Be concurrent-safe**: Use `ThreadPoolExecutor` for parallel operations
4. **Log progress**: Print status messages for CLI visibility
5. **Respect scope**: Check that the target is meaningful for your tool
6. **Validate input**: Return `STATUS_FAILED` for empty or invalid targets
7. **Use the schema**: Always use `Finding` and `tool_result()` from `nexus.foundation.schema`