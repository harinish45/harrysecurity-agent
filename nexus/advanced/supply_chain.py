"""Supply Chain Security Scanning — wraps ``pip-audit``.

Shells out to ``pip-audit --format=json -r <requirements_file>`` via
``nexus.tools.sandbox.run_subprocess`` (minimal inherited environment, real
whole-process-tree kill on timeout — the same treatment every other
external tool invocation in NEXUS gets) and turns its JSON output into
``Finding``-shaped dicts.

Severity: ``pip-audit``'s own JSON output does not include a CVSS score or
severity rating at all — a vulnerability entry is just
``{id, fix_versions, aliases, description}``. Rather than fabricate a
severity NEXUS didn't actually compute, every finding here defaults to
``severity="medium"`` and records that fact in
``raw["severity_note"]``, so nothing downstream mistakes "medium" for a
real assessment. A missing ``fix_versions`` list (no patched version
published yet) is called out explicitly in ``remediation`` instead, since
that is a real, available signal.

Availability: in this development environment, ``pip-audit`` is
``pip``-installed as a library but its console-script entry point is not on
PATH, and even ``python -m pip_audit`` times out here because it needs
network access to resolve the vulnerability database — so a live run is not
practical in this sandbox. ``scan()`` handles that exact situation
(executable not found, or the subprocess failing/timing out) the same way
it would handle any other missing/broken external tool: log a warning and
return ``[]`` rather than raise, so a caller aggregating results from many
scanners is not taken down by one missing dependency.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from nexus.tools.sandbox import SandboxError, run_subprocess

logger = logging.getLogger("nexus.advanced.supply_chain")

_DEFAULT_SEVERITY = "medium"


class SupplyChainScanner:
    """Runs ``pip-audit`` against a requirements file and normalizes the output."""

    def scan(self, requirements_file: str = "requirements.txt", *, timeout: float = 120) -> list[dict[str, Any]]:
        cmd = ["pip-audit", "--format=json", "-r", requirements_file]
        try:
            proc = run_subprocess(cmd, timeout=timeout)
        except SandboxError as exc:
            logger.warning("pip-audit failed to run: %s", exc)
            return []
        except FileNotFoundError:
            logger.warning("pip-audit executable not found on PATH; skipping supply-chain scan")
            return []
        except Exception:  # pragma: no cover - defensive, mirrors other tool wrappers
            logger.warning("Unexpected error running pip-audit", exc_info=True)
            return []

        # pip-audit exits 0 when clean, 1 when vulnerabilities were found —
        # both are a successful run for our purposes. Anything else (2+) is
        # a real failure (bad args, couldn't resolve requirements, etc).
        if proc.returncode not in (0, 1):
            logger.warning(
                "pip-audit exited with code %s: %s", proc.returncode, (proc.stdout or "")[:500]
            )
            return []

        try:
            payload = json.loads(proc.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Could not parse pip-audit JSON output: %s", exc)
            return []

        return self.parse_pip_audit_json(payload)

    def parse_pip_audit_json(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Turn a decoded ``pip-audit --format=json`` payload into Finding-shaped dicts.

        Split out from ``scan()`` so the parsing logic can be tested with a
        canned payload without shelling out (see tests/unit/advanced/).
        Expected shape (pip-audit's own JSON formatter):
        ``{"dependencies": [{"name", "version", "vulns": [{"id", "fix_versions", "aliases", "description"}]}]}``.
        """
        findings: list[dict[str, Any]] = []
        for dep in (payload or {}).get("dependencies", []) or []:
            if dep.get("skip_reason"):
                continue
            name = dep.get("name", "unknown")
            version = dep.get("version", "")
            for vuln in dep.get("vulns", []) or []:
                vuln_id = vuln.get("id", "UNKNOWN")
                fix_versions = vuln.get("fix_versions") or []
                remediation = (
                    f"Upgrade {name} to one of: {', '.join(fix_versions)}"
                    if fix_versions
                    else f"No fixed version published yet for {vuln_id}; monitor for a patch."
                )
                findings.append({
                    "id": f"SC-{vuln_id}",
                    "title": f"{name} {version}: {vuln_id}",
                    "severity": _DEFAULT_SEVERITY,
                    "confidence": "certain",
                    "affected_asset": name,
                    "evidence": vuln.get("description") or f"{vuln_id} affects {name} {version}",
                    "remediation": remediation,
                    "references": list(vuln.get("aliases") or []) + [vuln_id],
                    "tool": "supply_chain.pip_audit",
                    "tool_version": "",
                    "raw": {
                        "pip_audit_dependency": {"name": name, "version": version},
                        "pip_audit_vuln": vuln,
                        "severity_note": "pip-audit does not provide a severity rating; defaulted to medium.",
                    },
                })
        return findings
