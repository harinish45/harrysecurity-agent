"""Packages completed-phase results into a compact context dict to hand
forward to dependent phases. Before this, a phase's agent only ever saw its
own `task`/`target` — it had no idea what earlier phases had already found,
so e.g. a vuln-assessment phase couldn't know what assets recon had
discovered."""
from __future__ import annotations

from typing import Any


class ContextTransfer:
    @staticmethod
    def package(results: list[dict[str, Any]], *, limit_findings: int = 20) -> dict[str, Any]:
        findings: list[str] = []
        assets: set[str] = set()
        domains: set[str] = set()

        for r in results:
            if not isinstance(r, dict):
                continue
            for f in (r.get("findings") or [])[:limit_findings]:
                if isinstance(f, dict):
                    title = f.get("title")
                    asset = f.get("affected_asset")
                    if asset:
                        assets.add(str(asset))
                else:
                    title = str(f)
                if title:
                    findings.append(str(title))

            domain = r.get("domain") or str(r.get("agent", "")).replace("_agent", "")
            if domain:
                domains.add(domain)

        return {
            "prior_findings": findings[:limit_findings],
            "discovered_assets": sorted(assets),
            "completed_domains": sorted(domains),
        }
