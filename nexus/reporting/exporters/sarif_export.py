"""SARIF 2.1.0 export — uses the canonical Finding schema."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nexus.foundation.schema import normalize_findings


class SarifExport:
    """Export findings in SARIF 2.1.0 for code-scanning platforms."""

    def export(self, data: list[Any], output: str | Path) -> Path:
        findings = normalize_findings(data)
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
                        "artifactLocation": {"uri": item.get("affected_asset", "")},
                    }
                }],
                "properties": {
                    "severity": sev,
                    "confidence": item.get("confidence", "medium"),
                    "evidence": item.get("evidence", ""),
                    "remediation": item.get("remediation", ""),
                    "tool": item.get("tool", ""),
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