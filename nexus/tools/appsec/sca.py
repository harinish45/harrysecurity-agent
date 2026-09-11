#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec.sca
Domain: appsec
Software Composition Analysis: real dependency-manifest parsing plus a real
OSV.dev lookup per declared package+version. This is the same operation as
appsec.dependency_analysis under its more common industry name (SCA); the
real parsing/lookup logic lives once in nexus/tools/appsec/_manifest_scan.py
and both tools call it.

Previously this ignored `target` as a manifest/path entirely and did a bare
DNS resolve + HTTP GET on "/" (byte-for-byte identical to 19 other stub
tools) — caught during this session's audit. `target` is now honestly
reinterpreted as a local path (a manifest file or a source tree containing
one). A non-local-path target degrades to STATUS_OUT_OF_SCOPE instead of
fabricating results.
"""
from __future__ import annotations

from typing import Any

from nexus.tools.appsec._manifest_scan import scan_dependencies
from nexus.tools.registry import tool_registry


def run(target: str, max_packages: int = 200, **kwargs: Any) -> dict:
    """Software Composition Analysis: parse declared dependencies and check OSV.dev for known vulns.

    Parameters
    ----------
    target : str
        Path to a manifest file (requirements.txt, package.json,
        package-lock.json, Pipfile.lock) or a directory containing one.
    max_packages : int
        Maximum number of declared packages to check against OSV.dev.
    """
    return scan_dependencies("appsec.sca", target, max_packages=max_packages)


tool_registry.register("appsec.sca", run, metadata={
    "name": "appsec.sca",
    "domain": "appsec",
    "status": "completed",
    "description": "Software Composition Analysis: real dependency manifest parsing with OSV.dev "
                    "known-vulnerability lookup per package+version",
    "parameters": {
        "target": "Local path to a manifest file or a directory containing one",
        "max_packages": "Maximum declared packages to check against OSV.dev (default: 200)",
    },
})
