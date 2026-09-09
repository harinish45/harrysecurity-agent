"""Real Model Context Protocol server for NEXUS-STRIKE.

`nexus mcp` used to print "MCP Server implementation coming in Phase 2."
and exit — no protocol handshake, no tools, nothing a real MCP client
could connect to. This package is the real thing: a spec-compliant
server (built on the official `mcp` SDK) exposing a curated set of
NEXUS-STRIKE operations to any MCP client (Claude Desktop, Cursor,
Claude Code, etc.) over stdio or streamable-HTTP.
"""
from nexus.mcp.server import create_server

__all__ = ["create_server"]
