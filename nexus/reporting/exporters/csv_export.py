"""CSV export — uses the canonical Finding schema."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from nexus.foundation.schema import normalize_findings


FINDING_FIELDS = [
    "id", "title", "severity", "confidence", "affected_asset",
    "evidence", "remediation", "references", "timestamp", "tool", "tool_version",
]


class CsvExport:
    """Export findings for spreadsheet and ticketing workflows."""

    def export(self, data: list[Any], output: str | Path) -> Path:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        normalised = normalize_findings(data)
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=FINDING_FIELDS,
                extrasaction="ignore",
            )
            writer.writeheader()
            for item in normalised:
                row = {k: item.get(k, "") for k in FINDING_FIELDS}
                if isinstance(row.get("references"), list):
                    row["references"] = "; ".join(row["references"])
                writer.writerow(row)
        return path