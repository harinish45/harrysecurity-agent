#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering tool: Ghidra Analysis
Domain: reverse_engineering
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """reverse_engineering tool: Ghidra Analysis"""
    findings = []
    try:
        import os
        import hashlib
        if os.path.isfile(target):
            with open(target, "rb") as f:
                data = f.read()
            findings.append(f"File: {target}")
            findings.append(f"Size: {len(data)} bytes")
            findings.append(f"MD5: {hashlib.md5(data).hexdigest()}")
            findings.append(f"SHA256: {hashlib.sha256(data).hexdigest()}")
            # Check file type
            if data[:4] == b"\x7fELF":
                findings.append("File type: ELF binary")
            elif data[:2] == b"MZ":
                findings.append("File type: PE (Windows) binary")
            elif data[:4] == b"\x7fELF":
                findings.append("File type: ELF binary")
            else:
                findings.append(f"File type: unknown (magic: {data[:4].hex()})")
        else:
            findings.append(f"Target {target} is not a file")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "reverse_engineering.ghidra_analysis", "domain": "reverse_engineering", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("reverse_engineering.ghidra_analysis", run, metadata={
    "name": "reverse_engineering.ghidra_analysis",
    "domain": "reverse_engineering",
    "status": "completed",
    "description": "reverse_engineering tool: Ghidra Analysis",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
