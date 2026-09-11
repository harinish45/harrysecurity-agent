"""JSON export — uses the canonical Finding schema."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nexus.foundation.schema import normalize_findings, redact_findings


FINDING_FIELDS = [
    "id", "title", "severity", "confidence", "affected_asset",
    "evidence", "remediation", "references", "timestamp", "tool", "tool_version",
]


class JsonExport:
    """Export normalized findings as portable JSON evidence."""

    def export(self, data: list[Any], output: str | Path, redact: bool = True) -> Path:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        normalised = normalize_findings(data)
        if redact:
            normalised = redact_findings(normalised)
        payload = {
            "schema_version": "2.0",
            "exported_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finding_count": len(normalised),
            "findings": normalised,
        }
        path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
        return path