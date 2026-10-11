"""Packages completed-phase results into a compact context dict to hand
forward to dependent phases. Before this, a phase's agent only ever saw its
own `task`/`target` — it had no idea what earlier phases had already found,
so e.g. a vuln-assessment phase couldn't know what assets recon had
discovered."""
from __future__ import annotations

from typing import Any


import re
from typing import Any


class ContextTransfer:
    """Packages completed-phase results into structured context for downstream agents."""

    _PORT_RE = re.compile(r"\bport\s+(\d+)\b", re.IGNORECASE)

    @staticmethod
    def package(results: list[dict[str, Any]], *, limit_findings: int = 20) -> dict[str, Any]:
        if not results:
            return {
                "prior_findings": [],
                "discovered_assets": [],
                "completed_domains": [],
            }

        findings: list[str] = []
        assets: set[str] = set()
        domains: set[str] = set()
        ports: set[int] = set()

        for r in results:
            if not isinstance(r, dict):
                continue
            for f in (r.get("findings") or [])[:limit_findings]:
                if isinstance(f, dict):
                    title = f.get("title")
                    asset = f.get("affected_asset")
                    if asset:
                        assets.add(str(asset))
                    text = f"{title or ''} {f.get('evidence', '')}"
                    for m in ContextTransfer._PORT_RE.finditer(text):
                        try:
                            val = int(m.group(1))
                            if 1 <= val <= 65535:
                                ports.add(val)
                        except (ValueError, TypeError):
                            pass
                else:
                    title = str(f)
                    for m in ContextTransfer._PORT_RE.finditer(title):
                        try:
                            val = int(m.group(1))
                            if 1 <= val <= 65535:
                                ports.add(val)
                        except (ValueError, TypeError):
                            pass
                if title:
                    findings.append(str(title))

            domain = r.get("domain") or str(r.get("agent", "")).replace("_agent", "")
            if domain:
                domains.add(domain)

        context_data: dict[str, Any] = {
            "prior_findings": findings[:limit_findings],
            "discovered_assets": sorted(assets),
            "completed_domains": sorted(domains),
        }
        if ports:
            context_data["discovered_ports"] = sorted(ports)
        return context_data

