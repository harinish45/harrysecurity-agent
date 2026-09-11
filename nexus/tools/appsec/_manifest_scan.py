#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec._manifest_scan
Shared, real dependency-manifest parsing + OSV.dev lookup used by both
appsec.dependency_analysis and appsec.sca (they are the same operation —
Software Composition Analysis — under two names, so the real logic lives
here once instead of being forked twice).

Real parsing of requirements.txt / package.json / package-lock.json /
Pipfile.lock for *declared, pinned* package versions, then a real query
against the free OSV.dev API (https://api.osv.dev/v1/query, no API key
required) for known vulnerabilities per package+version. Not registered as
a tool itself.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    STATUS_FAILED,
    tool_result,
)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"

_MANIFEST_KINDS = {
    "requirements.txt": "pip_requirements",
    "package.json": "npm_package",
    "package-lock.json": "npm_lock",
    "Pipfile.lock": "pipfile_lock",
}
_EXCLUDED_DIRS = {".git", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
_MAX_MANIFESTS = 25
_MAX_PACKAGES_DEFAULT = 200

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+]+)")


# ── Manifest discovery ───────────────────────────────────────────────────

def discover_manifests(path: str) -> list[tuple[str, str]]:
    """Find dependency manifests under `path` (a file or directory)."""
    found: list[tuple[str, str]] = []
    if os.path.isfile(path):
        kind = _MANIFEST_KINDS.get(os.path.basename(path))
        if kind:
            found.append((path, kind))
        return found

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for fname in files:
            kind = _MANIFEST_KINDS.get(fname)
            if kind:
                found.append((os.path.join(root, fname), kind))
                if len(found) >= _MAX_MANIFESTS:
                    return found
    return found


# ── Manifest parsing (real, per-format) ──────────────────────────────────

def _parse_requirements_txt(path: str) -> list[tuple[str, str, str, str]]:
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = _REQ_LINE_RE.match(line)
                if m:
                    out.append((m.group(1), m.group(2), "PyPI", path))
    except OSError:
        pass
    return out


def _parse_package_json(path: str) -> list[tuple[str, str, str, str]]:
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out
    if not isinstance(data, dict):
        return out
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            # Best-effort: strip leading semver-range symbols (^, ~, >=, etc.)
            # to approximate the pinned/minimum version. Ranges without a
            # concrete leading version (e.g. "*", "latest") are skipped
            # rather than guessed at.
            version = re.sub(r"^[^\d]*", "", str(spec))
            if version and re.match(r"^\d", version):
                out.append((name, version, "npm", path))
    return out


def _parse_package_lock_json(path: str) -> list[tuple[str, str, str, str]]:
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out
    if not isinstance(data, dict):
        return out
    packages = data.get("packages")
    if isinstance(packages, dict):
        # npm lockfile v2/v3: keys are paths like "node_modules/lodash"
        for pkg_path, info in packages.items():
            if not pkg_path or "node_modules/" not in pkg_path + "/":
                continue
            if not isinstance(info, dict):
                continue
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            version = info.get("version")
            if name and version:
                out.append((name, version, "npm", path))
    else:
        # npm lockfile v1: top-level "dependencies" map
        deps = data.get("dependencies") or {}
        for name, info in deps.items():
            version = info.get("version") if isinstance(info, dict) else None
            if version:
                out.append((name, version, "npm", path))
    return out


def _parse_pipfile_lock(path: str) -> list[tuple[str, str, str, str]]:
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out
    if not isinstance(data, dict):
        return out
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version", "")).lstrip("=")
            if version:
                out.append((name, version, "PyPI", path))
    return out


_PARSERS = {
    "pip_requirements": _parse_requirements_txt,
    "npm_package": _parse_package_json,
    "npm_lock": _parse_package_lock_json,
    "pipfile_lock": _parse_pipfile_lock,
}


def parse_manifest(path: str, kind: str) -> list[tuple[str, str, str, str]]:
    """Return [(name, version, ecosystem, source_path), ...] declared in `path`."""
    return _PARSERS.get(kind, lambda p: [])(path)


# ── OSV.dev lookup (real, free, no API key) ──────────────────────────────

def query_osv(name: str, version: str, ecosystem: str, timeout: float = 10) -> list[dict[str, Any]]:
    """Real POST to https://api.osv.dev/v1/query for known vulns in name@version."""
    payload = json.dumps({"version": version, "package": {"name": name, "ecosystem": ecosystem}}).encode("utf-8")
    req = urllib.request.Request(
        _OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "NexusStrike/1.0"},
        method="POST",
    )
    resp = safe_urlopen(req, timeout=timeout)
    body = resp.read(1_000_000).decode("utf-8", errors="replace")
    doc = json.loads(body)
    return doc.get("vulns", []) or []


def _severity_for(vulns: list[dict[str, Any]]) -> str:
    # OSV's `severity` field carries CVSS *vectors*, not a bare numeric score,
    # so parsing an exact number back out of it would overclaim precision.
    # This is a deliberately coarse approximation: an advisory that OSV or
    # its upstream database itself labels CRITICAL is reported as such,
    # everything else with any advisory is "high" rather than invented.
    text = json.dumps(vulns).upper()
    return "critical" if "CRITICAL" in text else "high"


# ── Shared scan entrypoint used by dependency_analysis.py and sca.py ─────

def scan_dependencies(tool_name: str, target: str, max_packages: int = _MAX_PACKAGES_DEFAULT) -> dict:
    path = (target or "").strip()
    if not path:
        return tool_result(tool_name, target, status=STATUS_FAILED, error="Empty target")

    if not os.path.exists(path):
        return tool_result(
            tool_name, target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"{path} is not a local path — dependency analysis requires a local source tree or "
                    f"manifest file (requirements.txt, package.json, package-lock.json, Pipfile.lock), "
                    f"not a network target.",
        )

    manifests = discover_manifests(path)
    if not manifests:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"No dependency manifest (requirements.txt, package.json, package-lock.json, "
                    f"Pipfile.lock) found under {path}.",
        )

    packages: list[tuple[str, str, str, str]] = []
    for mpath, kind in manifests:
        packages.extend(parse_manifest(mpath, kind))
    packages = packages[:max_packages]

    findings: list[Finding] = []
    vulnerable_count = 0
    query_errors = 0
    checked = 0

    for name, version, ecosystem, source in packages:
        if not version:
            continue
        checked += 1
        try:
            vulns = query_osv(name, version, ecosystem)
        except Exception:  # noqa: BLE001 - network failures cover many exception types
            query_errors += 1
            continue
        if vulns:
            vulnerable_count += 1
            ids = [v.get("id", "?") for v in vulns]
            summary_bits = "; ".join(v.get("summary", "")[:100] for v in vulns if v.get("summary"))[:300]
            findings.append(Finding(
                title=f"Known vulnerability in {name}=={version}",
                severity=_severity_for(vulns),
                confidence="high",
                affected_asset=source,
                evidence=f"OSV.dev reports {len(vulns)} advisory(ies) for {ecosystem} package "
                         f"{name}=={version}: {', '.join(ids)}. {summary_bits}",
                remediation=f"Upgrade {name} beyond the affected version range documented in the OSV advisory.",
                tool=tool_name,
                references=[f"https://osv.dev/vulnerability/{i}" for i in ids],
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    err_note = f" ({query_errors} OSV.dev query error(s))" if query_errors else ""
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Parsed {checked} pinned dependenc{'y' if checked == 1 else 'ies'} from "
                f"{len(manifests)} manifest(s) under {path}; {vulnerable_count} had known OSV.dev "
                f"advisories{err_note}.",
        metadata={
            "manifests_found": [m for m, _ in manifests],
            "packages_checked": checked,
            "vulnerable_packages": vulnerable_count,
            "osv_query_errors": query_errors,
        },
    )
