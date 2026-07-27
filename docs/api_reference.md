# API Reference

## CLI Commands

### `nexus run`
Run a security assessment mission through the orchestration engine.

```
nexus run --target <target> [options]
```

**Options:**
- `--target, -t` (required): Target domain, IP, or URL
- `--engagement, -e`: Engagement JSON file path
- `--mode, -m`: Execution mode (guided, autonomous, tool, interactive)
- `--mission, --id`: Mission identifier
- `--objective, -o`: Mission objective (full_assessment, quick_scan, vuln_scan, osint)
- `--provider, -p`: LLM provider override

### `nexus live`
Run the live AI cybersecurity agent with real tools.

```
nexus live --target <target> [options]
```

**Options:**
- `--target, -t`: Target IP or hostname (default: 127.0.0.1)
- `--host, -H`: Target hostname for DNS resolution (default: localhost)
- `--ports, -p`: Comma-separated port list
- `--llm-url`: LLM gateway URL override
- `--llm-model`: LLM model name override

### `nexus engage`
Create an authorized engagement record.

```
nexus engage --client <name> --scope <targets> --authorization-reference <ref>
```

### `nexus preflight`
Check environment readiness for authorized assessment.

### `nexus tools`
List all registered tools in the Tool Fabric.

### `nexus agents`
List all registered agents in the Agent Mesh.

### `nexus providers`
Show LLM provider configuration status.

### `nexus config-show`
Show current NEXUS-STRIKE configuration.

### `nexus verify`
Run offline integrity check for all bundled tools.

### `nexus export-report`
Export findings to portable format.

```
nexus export-report <source.json> --format <json|csv|html|sarif> --output <path>
```

## Programmatic API

### Tool Registry

```python
from nexus.tools.registry import tool_registry

# List all tools
tools = tool_registry.list_tools()

# Get a specific tool
tool_fn = tool_registry.get("network.port_scan")
result = tool_fn(target="127.0.0.1")

# List tools by domain
webapp_tools = tool_registry.list_by_domain("webapp")
```

### Tool Executor

```python
from nexus.tools.executor import ToolExecutor

executor = ToolExecutor()
result = executor.run("network.port_scan", target="127.0.0.1")
```

### Orchestration Engine

```python
import asyncio
from nexus.orchestration.engine import OrchestrationEngine

engine = OrchestrationEngine(llm_provider="ollama")
result = asyncio.run(engine.run_mission(
    target="127.0.0.1",
    mission_id="my-mission",
    mode="guided",
    objective="quick_scan",
))
```

### Live Agent

```python
from scripts.live_agent import run_assessment

result = run_assessment(target_ip="127.0.0.1", target_host="localhost")
```

### Finding Schema

```python
from nexus.foundation.schema import Finding, tool_result

finding = Finding(
    title="Open port 22 (SSH)",
    severity="high",
    confidence="certain",
    affected_asset="127.0.0.1:22",
    evidence="Port 22 is open and responding",
    remediation="Restrict SSH access or disable if not needed",
    tool="network.port_scan",
)

result = tool_result(
    "network.port_scan",
    "127.0.0.1",
    findings=[finding],
    summary="Found 3 open ports",
)
```

### Guardrails

```python
from nexus.foundation.guardrails import ScopeGuard, LegalGuard, RateGuard

# Check if target is in scope
ScopeGuard.validate("127.0.0.1")

# Check legal authorization
LegalGuard.validate(target="127.0.0.1")

# Check rate limits
RateGuard.validate(target="127.0.0.1")