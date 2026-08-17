#!/usr/bin/env python3
"""Generate a professional white-label NEXUS-STRIKE PDF report."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from nexus.reporting.professional import ReportBranding, render_pdf


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Assessment JSON")
    parser.add_argument("--output", type=Path, required=True, help="Output PDF")
    parser.add_argument("--organization", default="Security Assessment")
    parser.add_argument("--title", default="Security Assessment Report")
    parser.add_argument("--classification", default="CONFIDENTIAL")
    parser.add_argument("--accent", default="#2463a6")
    parser.add_argument("--logo-text", default="NEXUS-STRIKE")
    args = parser.parse_args()

    data = json.loads(args.input.read_text(encoding="utf-8"))
    branding = ReportBranding(
        organization_name=args.organization,
        report_title=args.title,
        classification=args.classification,
        accent=args.accent,
        logo_text=args.logo_text,
        footer=f"{args.organization} • Security Assessment",
    )
    render_pdf(data, args.output, branding)
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
