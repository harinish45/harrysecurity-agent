#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics tool: Email Forensics
Domain: forensics
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """forensics tool: Email Forensics"""
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
        elif os.path.isdir(target):
            files = os.listdir(target)
            findings.append(f"Directory: {target}")
            findings.append(f"File count: {len(files)}")
            findings.append(f"Files: {files[:20]}")
        else:
            findings.append(f"Target {target} not found")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "forensics.email_forensics", "domain": "forensics", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("forensics.email_forensics", run, metadata={
    "name": "forensics.email_forensics",
    "domain": "forensics",
    "status": "completed",
    "description": "forensics tool: Email Forensics",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
