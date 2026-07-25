"""PDF export via an approved rendering backend."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from nexus.foundation.schema import normalize_findings
from nexus.reporting.exporters.html_export import HtmlExport


class PdfExport:
    """Export findings as PDF via an approved rendering backend.

    Backend resolution order:
    1. ``weasyprint`` (Python library, best quality)
    2. ``playwright`` (headless Chromium, good fallback)
    3. ``wkhtmltopdf`` (CLI tool, legacy)
    """

    def export(self, data: list[Any], output: str | Path, title: str = "NEXUS-STRIKE Security Assessment Report") -> Path:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Render HTML first
        html_path = path.with_suffix(".html")
        HtmlExport().export(data, html_path, title=title)
        html_content = html_path.read_text(encoding="utf-8")

        # Try backends in order
        if self._try_weasyprint(html_content, path):
            return path
        if self._try_playwright(html_path, path):
            return path
        if self._try_wkhtmltopdf(html_path, path):
            return path

        raise RuntimeError(
            "No PDF rendering backend available. Install one of:\n"
            "  pip install weasyprint\n"
            "  pip install playwright && playwright install chromium\n"
            "  or install wkhtmltopdf from https://wkhtmltopdf.org/"
        )

    @staticmethod
    def _try_weasyprint(html: str, output: Path) -> bool:
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
            HTML(string=html).write_pdf(str(output))
            return True
        except ImportError:
            return False
        except Exception as exc:
            print(f"[PDF] weasyprint failed: {exc}", file=sys.stderr)
            return False

    @staticmethod
    def _try_playwright(html_path: Path, output: Path) -> bool:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore[import-untyped]
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(html_path.as_uri(), wait_until="networkidle")
                page.pdf(path=str(output), format="A4", print_background=True)
                browser.close()
            return True
        except ImportError:
            return False
        except Exception as exc:
            print(f"[PDF] playwright failed: {exc}", file=sys.stderr)
            return False

    @staticmethod
    def _try_wkhtmltopdf(html_path: Path, output: Path) -> bool:
        try:
            subprocess.run(
                ["wkhtmltopdf", str(html_path), str(output)],
                capture_output=True,
                timeout=60,
                check=True,
            )
            return True
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            print(f"[PDF] wkhtmltopdf failed: {exc}", file=sys.stderr)
            return False