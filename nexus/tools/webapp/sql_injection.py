#!/usr/bin/env python3
"""
NEXUS-STRIKE — webapp.sql_injection
Domain: webapp
Alias for webapp.sqli to maintain backward compatibility and registry consistency.
"""
from __future__ import annotations
from typing import Any
from nexus.tools.registry import tool_registry

# Import the actual implementation
from nexus.tools.webapp.sqli import run as sqli_run

def run(target: str, **kwargs: Any) -> dict:
    """Perform SQL injection testing (alias to webapp.sqli)."""
    # Delegate to the real implementation
    return sqli_run(target, **kwargs)

tool_registry.register("webapp.sql_injection", run, metadata={
    "name": "webapp.sql_injection",
    "domain": "webapp",
    "status": "completed",
    "description": "SQL Injection detection (alias to webapp.sqli)",
    "parameters": {
        "target": "Target URL or hostname to test",
        "max_params": "Maximum parameters to test (default: 10)",
        "max_payloads": "Maximum payloads per parameter (default: 50)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})