#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering.binary_patching
Domain: reverse_engineering

Binary patching (assembling a replacement instruction sequence and writing
it back into a target binary — NOP-ing a check, redirecting a jump, etc.)
requires both write access to the target file and an assembler/disassembler
context (capstone/keystone) to compute a semantically correct patch — this
previously ignored `target` entirely and reported generic file-magic/hash
output as if patching had occurred, always with status "completed" —
caught during this session's audit (byte-for-byte identical to
debugging.py, assembly_analysis.py, etc. before this fix).

This tool deliberately never writes to a target file as a side effect of
a routine assessment run — patching a binary is a deliberate, destructive,
opt-in action, not something a passive security tool should do implicitly.
Instead it performs a real prerequisite check (is `target` an existing,
writable local file, and is `capstone` available for validating patch
offsets against real instruction boundaries) and honestly reports
STATUS_UNAVAILABLE when a real, safe patch cannot be constructed, rather
than fabricating a "patch applied" result.
"""
from __future__ import annotations

import os
from typing import Any

from nexus.foundation.schema import STATUS_FAILED, STATUS_UNAVAILABLE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs: Any) -> dict:
    """reverse_engineering tool: binary patching prerequisite check (never writes implicitly)."""
    if not os.path.isfile(target):
        return tool_result("reverse_engineering.binary_patching", target, status=STATUS_FAILED,
                            error=f"File not found: {target}")

    writable = os.access(target, os.W_OK)
    try:
        import capstone  # noqa: F401
        capstone_available = True
    except ImportError:
        capstone_available = False

    reasons = []
    if not writable:
        reasons.append("target file is not writable by the current user")
    if not capstone_available:
        reasons.append("capstone is not installed — cannot validate patch offsets against real instruction boundaries")
    if "patch_bytes" not in kwargs or "offset" not in kwargs:
        reasons.append("no explicit patch_bytes/offset supplied — this tool never patches a "
                        "binary implicitly as a side effect of a routine scan")

    return tool_result(
        "reverse_engineering.binary_patching", target,
        status=STATUS_UNAVAILABLE,
        summary=f"Binary patching for {target} was not performed: {'; '.join(reasons)}",
        error="unavailable: " + "; ".join(reasons),
        metadata={
            "target_writable": writable,
            "capstone_available": capstone_available,
            "note": "This tool intentionally requires explicit patch_bytes/offset kwargs and "
                    "never mutates a target file as a side effect of an assessment run.",
        },
    )


tool_registry.register("reverse_engineering.binary_patching", run, metadata={
    "name": "reverse_engineering.binary_patching",
    "domain": "reverse_engineering",
    "status": "unavailable",
    "description": "Binary patching prerequisite check (write access + capstone availability) — never patches implicitly; requires explicit patch_bytes/offset",
    "parameters": {
        "target": "Path to the target binary file",
        "offset": "Explicit file offset to patch (required to actually patch)",
        "patch_bytes": "Explicit replacement bytes (required to actually patch)",
    },
})
