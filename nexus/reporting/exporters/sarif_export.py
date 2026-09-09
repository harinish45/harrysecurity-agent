"""SARIF 2.1.0 export — uses the canonical Finding schema."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from nexus.foundation.schema import normalize_findings, redact_findings

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _as_uri(affected_asset: str) -> str:
    """`affected_asset` is often a bare host:port ("10.0.0.1:22") or plain
    hostname — not a syntactically valid URI per the SARIF 2.1.0 spec's
    `artifactLocation.uri` field, which some strict SARIF consumers reject.
    Pass through anything that already has a scheme; wrap anything else in
    a neutral scheme so it's always at least well-formed."""
    asset = affected_asset or "unknown"
    if _SCHEME_RE.match(asset):
        return asset
    return f"asset://{asset}"


class SarifExport:
    """Export findings in SARIF 2.1.0 for code-scanning platforms."""

    def export(self, data: list[Any], output: str | Path, redact: bool = True) -> Path:
        findings = normalize_findings(data)
        if redact:
            findings = redact_findings(findings)
        rules = []
        results = []
        seen_rules: set[str] = set()

        for item in findings:
            rule_id = item.get("id", "F-000")
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": item.get("title", "")[:200]},
                    "properties": {
                        "severity": item.get("severity", "info"),
                        "confidence": item.get("confidence", "medium"),
                        "remediation": item.get("remediation", ""),
                    },
                })

            sev = item.get("severity", "info")
            level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": item.get("title", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _as_uri(item.get("affected_asset", ""))},
                    }
                }],
                "properties": {
                    "severity": sev,
                    "confidence": item.get("confidence", "medium"),
                    "evidence": item.get("evidence", ""),
                    "remediation": item.get("remediation", ""),
                    "tool": item.get("tool", ""),
                    # Populated by the post-processing agents (verification_agent,
                    # blast_radius_agent, mitre_mapping_agent, attack_chain_agent)
                    # — carried through so SARIF consumers get the same
                    # annotation depth as the HTML/Markdown reports (see
                    # html_export.py's _build_rows/_build_chains and
                    # generator.py), instead of silently dropping it.
                    "verificationStatus": item.get("verification_status", ""),
                    "verificationDetail": item.get("verification_detail", ""),
                    "businessImpact": item.get("business_impact", ""),
                    "mitreTechniques": item.get("mitre_techniques") or [],
                    "kind": item.get("kind", ""),
                    "chainAssets": item.get("chain_assets") or [],
                },
            })

        document = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "NEXUS-STRIKE",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/nexus-strike/nexus-strike",
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2, default=str) + "\n", encoding="utf-8")
        return path