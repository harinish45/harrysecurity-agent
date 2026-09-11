#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering tool: Ida Analysis
Domain: reverse_engineering

Previously claimed to be "IDA Analysis" while never invoking IDA Pro at
all — just file-magic/hash inspection. Unlike Ghidra (open-source, has a
free scriptable headless CLI), IDA Pro is a licensed commercial product
with no legitimate free headless path — there's nothing safe to
auto-detect-and-invoke the way ghidra_analysis.py now does. Kept as honest
static analysis with an explicit note that real IDA disassembly did not
happen, rather than pretending otherwise.
"""
import hashlib
import os

from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """reverse_engineering tool: Ida Analysis"""
    findings = []
    try:
        if os.path.isfile(target):
            with open(target, "rb") as f:
                data = f.read()
            findings.append(f"File: {target}")
            findings.append(f"Size: {len(data)} bytes")
            findings.append(f"MD5: {hashlib.md5(data, usedforsecurity=False).hexdigest()}")
            findings.append(f"SHA256: {hashlib.sha256(data).hexdigest()}")
            if data[:4] == b"\x7fELF":
                findings.append("File type: ELF binary")
            elif data[:2] == b"MZ":
                findings.append("File type: PE (Windows) binary")
            else:
                findings.append(f"File type: unknown (magic: {data[:4].hex()})")
            findings.append(
                "Static magic-byte/hash analysis only — IDA Pro is a licensed product with no "
                "headless invocation available here. Full disassembly/decompilation was not performed."
            )
        else:
            findings.append(f"Target {target} is not a file")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "reverse_engineering.ida_analysis", "domain": "reverse_engineering", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("reverse_engineering.ida_analysis", run, metadata={
    "name": "reverse_engineering.ida_analysis",
    "domain": "reverse_engineering",
    "status": "completed",
    "description": "reverse_engineering tool: honest static magic-byte/hash analysis (no headless IDA path exists to invoke)",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
