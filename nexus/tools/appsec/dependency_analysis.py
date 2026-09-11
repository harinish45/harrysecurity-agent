#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec.dependency_analysis
Domain: appsec
Real dependency-manifest parsing (requirements.txt, package.json,
package-lock.json, Pipfile.lock) plus a real OSV.dev lookup per declared
package+version.

Previously this ignored `target` as a manifest/path entirely and did a bare
DNS resolve + HTTP GET on "/" (byte-for-byte identical to 19 other stub
tools) — caught during this session's audit. `target` is now honestly
reinterpreted as a local path (a manifest file or a source tree containing
one), since "what versions of what packages does this codebase declare" is
not a network-observable property. A non-local-path target degrades to
STATUS_OUT_OF_SCOPE instead of fabricating results.
"""
from __future__ import annotations

from typing import Any

from nexus.tools.appsec._manifest_scan import scan_dependencies
from nexus.tools.registry import tool_registry


def run(target: str, max_packages: int = 200, **kwargs: Any) -> dict:
    """Parse declared dependencies from a local manifest/source tree and check OSV.dev for known vulns.

    Parameters
    ----------
    target : str
        Path to a manifest file (requirements.txt, package.json,
        package-lock.json, Pipfile.lock) or a directory containing one.
    max_packages : int
        Maximum number of declared packages to check against OSV.dev.
    """
    return scan_dependencies("appsec.dependency_analysis", target, max_packages=max_packages)


tool_registry.register("appsec.dependency_analysis", run, metadata={
    "name": "appsec.dependency_analysis",
    "domain": "appsec",
    "status": "completed",
    "description": "Real dependency manifest parsing (requirements.txt/package.json/package-lock.json/"
                    "Pipfile.lock) with OSV.dev known-vulnerability lookup per package+version",
    "parameters": {
        "target": "Local path to a manifest file or a directory containing one",
        "max_packages": "Maximum declared packages to check against OSV.dev (default: 200)",
    },
})
