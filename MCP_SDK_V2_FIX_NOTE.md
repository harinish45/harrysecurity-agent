# MCP SDK v2 compatibility note

The NEXUS-STRIKE MCP control plane targets the MCP Python SDK 2.x API.

The SDK v2 renamed `FastMCP` to `MCPServer` and moved the implementation from `mcp.server.fastmcp` to `mcp.server.mcpserver`.

See `nexus/mcp_server.py` for the v2-compatible implementation.
