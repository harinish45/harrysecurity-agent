#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.registry_analysis
Domain: forensics
Real Windows registry hive parsing: if either the `python-registry`
(`Registry` module) or `regipy` library is installed, and target is a real
hive file (starts with the "regf" magic header), performs a minimal parse
(root key + shallow subkey listing). Neither library is declared in
requirements.txt nor installed in this environment, so this honestly
degrades — explaining a real exported .reg/hive file (and one of those
libraries) is needed — matching reverse_engineering.disassemble's
capstone-missing pattern.
"""
from __future__ import annotations
import os
from typing import Any
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

HIVE_MAGIC = b"regf"
MAX_SUBKEYS = 100


def run(target: str, **kwargs: Any) -> dict:
    """Parse a local Windows registry hive file (requires python-registry or regipy)."""
    if not target or not os.path.isfile(target):
        return tool_result(
            "forensics.registry_analysis", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a readable local file — registry analysis requires a real "
                    "exported registry hive file (e.g. NTUSER.DAT, SYSTEM, SOFTWARE), not a "
                    "network target.",
            error="target is not a local file",
        )

    try:
        with open(target, "rb") as f:
            head = f.read(4)
    except OSError as e:
        return tool_result("forensics.registry_analysis", target, status=STATUS_FAILED, error=str(e))

    if head != HIVE_MAGIC:
        return tool_result(
            "forensics.registry_analysis", target,
            status=STATUS_UNAVAILABLE,
            summary="File does not start with the 'regf' hive-file magic header — not a real "
                    "exported registry hive. Export one with, e.g., "
                    "`reg save HKLM\\SYSTEM system.hiv` and pass that file as the target.",
            error="not a registry hive file",
        )

    parser_lib = None
    try:
        from Registry import Registry as reg_lib  # python-registry
        parser_lib = "python-registry"
    except ImportError:
        try:
            import regipy  # noqa: F401
            parser_lib = "regipy"
        except ImportError:
            parser_lib = None

    if parser_lib is None:
        return tool_result(
            "forensics.registry_analysis", target,
            status=STATUS_UNAVAILABLE,
            findings=[Finding(
                title="No registry-hive parsing library installed",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence="Neither 'python-registry' nor 'regipy' is installed, and neither is "
                         "declared in requirements.txt. A valid hive file was found ('regf' magic "
                         "header present), so a real parse would be possible with either library "
                         "installed.",
                remediation="pip install python-registry   (or)   pip install regipy",
                tool="forensics.registry_analysis",
                references=[],
            )],
            summary="Registry analysis unavailable: no hive-parsing library installed "
                    "(target hive file is valid).",
            metadata={"hive_magic_valid": True},
        )

    try:
        if parser_lib == "python-registry":
            hive = reg_lib.Registry(target)
            root = hive.root()
            subkeys = [k.name() for k in root.subkeys()][:MAX_SUBKEYS]
        else:
            from regipy.registry import RegistryHive
            hive = RegistryHive(target)
            subkeys = [sk.name for sk in hive.root.iter_subkeys()][:MAX_SUBKEYS]
    except Exception as e:
        return tool_result("forensics.registry_analysis", target, status=STATUS_FAILED, error=f"Hive parse failed: {e}")

    findings = [Finding(
        title="Registry hive parsed",
        severity="info",
        confidence="certain",
        affected_asset=target,
        evidence=f"Parsed hive root; found {len(subkeys)} top-level subkey(s) via {parser_lib}: {subkeys}",
        remediation="Review subkeys of interest (Run keys, services, USB device history, etc.) for persistence/IOCs.",
        tool="forensics.registry_analysis",
    )] if subkeys else []

    status = STATUS_COMPLETED if subkeys else STATUS_NO_FINDINGS
    return tool_result(
        "forensics.registry_analysis", target,
        status=status,
        findings=findings,
        summary=f"Parsed hive via {parser_lib}; {len(subkeys)} top-level subkey(s) found.",
        metadata={"parser": parser_lib, "subkeys": subkeys},
    )


tool_registry.register("forensics.registry_analysis", run, metadata={
    "name": "forensics.registry_analysis",
    "domain": "forensics",
    "status": "completed",
    "description": "Parses a real exported Windows registry hive file (requires python-registry or regipy, neither installed by default)",
    "parameters": {"target": "Path to a local, real exported registry hive file (regf magic header)"},
})
