# NEXUS-STRIKE MCP Control Plane

NEXUS-STRIKE exposes a read-only Model Context Protocol (MCP) server for desktop and IDE clients.

## Start

After installing the project:

```bash
nexus-mcp
```

The server uses MCP stdio transport, which is the safest default for local desktop/IDE integrations because it does not open a network listener.

## Exposed surface

### Resources

- `nexus://status` — tool count, agent count, provider name and preflight readiness.
- `nexus://tools` — registered tool inventory.

### Tools

- `list_security_tools(domain?)` — inspect registered tools; never executes one.
- `platform_status()` — inspect non-secret runtime and guardrail readiness.
- `list_agents_readonly()` — inspect registered agent names and availability.

## Security boundary

MCP is deliberately **not** an execution bypass. The server does not expose arbitrary shell execution, direct tool invocation, mission execution, credential access, or sandbox-policy mutation.

Any future write-capable MCP surface must route through the same authorization, scope, legal acknowledgement, escalation, rate, audit and output guardrails used by the normal mission engine. It must also use the trusted runtime adapter rather than merely constructing a sandbox policy.

## Client configuration

For clients that accept a local stdio MCP server, configure the command as:

```json
{
  "mcpServers": {
    "nexus-strike": {
      "command": "nexus-mcp"
    }
  }
}
```

If the command is not on the client's PATH, use the absolute path to the installed executable or invoke the project's Python environment explicitly.
