"""PDF export via an approved rendering backend."""
from __future__ import annotations

import re
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
    4. ``xhtml2pdf`` (pure-Python, no native/system deps — last-resort
       fallback so PDF export never hard-fails just because the host is
       missing weasyprint's GTK libs, a Chromium install, or the
       wkhtmltopdf binary. Weaker CSS support than the others, so
       ``_try_xhtml2pdf`` strips the small set of rules xhtml2pdf's
       reportlab-based renderer can't parse (CSS custom properties /
       flexbox/grid, both used by html_export.py's layout) rather than
       let a parse error take the whole export down.)
    """

    def export(
        self,
        data: list[Any],
        output: str | Path,
        title: str = "NEXUS-STRIKE Security Assessment Report",
        redact: bool = True,
        include_visualizations: bool = True,
    ) -> Path:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Render HTML first — redaction and visualizations are handled once,
        # here, by HtmlExport; PdfExport just rasterizes its output.
        html_path = path.with_suffix(".html")
        HtmlExport().export(
            data, html_path, title=title, redact=redact, include_visualizations=include_visualizations
        )
        html_content = html_path.read_text(encoding="utf-8")

        # Try backends in order
        if self._try_weasyprint(html_content, path):
            return path
        if self._try_playwright(html_path, path):
            return path
        if self._try_edge_or_chrome(html_path, path):
            return path
        if self._try_wkhtmltopdf(html_path, path):
            return path
        if self._try_xhtml2pdf(html_content, path):
            return path

        raise RuntimeError(
            "No PDF rendering backend available. Install one of:\n"
            "  pip install weasyprint\n"
            "  pip install playwright && playwright install chromium\n"
            "  Microsoft Edge or Google Chrome (headless print-to-pdf)\n"
            "  pip install xhtml2pdf\n"
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
    def _try_edge_or_chrome(html_path: Path, output: Path) -> bool:
        """Microsoft Edge / Google Chrome headless print-to-pdf.
        Available natively on Windows (Microsoft Edge) and environments with Chrome/Edge.
        Produces high-fidelity, CSS3-compliant vector PDF output.
        """
        import shutil
        import tempfile

        candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            "msedge",
            "google-chrome",
            "chromium-browser",
            "chromium",
        ]
        executable = None
        for cand in candidates:
            if Path(cand).is_file():
                executable = cand
                break
            resolved = shutil.which(cand)
            if resolved:
                executable = resolved
                break

        if not executable:
            return False

        temp_profile = tempfile.mkdtemp(prefix="nexus_pdf_")
        try:
            cmd = [
                executable,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                f"--user-data-dir={temp_profile}",
                f"--print-to-pdf={output.resolve()}",
                html_path.resolve().as_uri(),
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode == 0 and output.exists() and output.stat().st_size > 0:
                return True
        except Exception as exc:
            print(f"[PDF] edge/chrome print-to-pdf failed: {exc}", file=sys.stderr)
        finally:
            shutil.rmtree(temp_profile, ignore_errors=True)

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

    # xhtml2pdf's CSS parser (reportlab-based) chokes on anything past
    # CSS 2.1 — no ``:not()``, no custom properties, no ``@media`` blocks,
    # no flexbox/grid, no ``position: sticky`` — all of which html_export.py
    # uses for its dark-mode/sticky-filter-bar/collapsible-chain layout.
    # Rather than let a parse error take the whole export down, swap in a
    # minimal print-safe stylesheet covering the same class names and
    # flatten <details>/<summary> (a static PDF has no use for a collapse
    # toggle anyway) before handing the markup to xhtml2pdf.
    _PDF_SAFE_CSS = """
        body { font-family: Helvetica, Arial, sans-serif; font-size: 10pt; color: #1a1a2e; }
        .container { padding: 12px; }
        h1 { font-size: 20pt; color: #0f3460; }
        h2 { font-size: 14pt; color: #16213e; margin-top: 16px; border-bottom: 1px solid #888; }
        .subtitle { color: #555; font-size: 9pt; }
        .card, .chain-item, .summary-cards { border: 1px solid #ccc; padding: 8px; margin-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 10px; }
        th, td { border: 1px solid #ccc; padding: 4px 6px; font-size: 9pt; text-align: left; }
        th { background-color: #eee; }
        .badge, .tag, .mitre-chip { display: inline; padding: 1px 5px; border: 1px solid #999; font-size: 8pt; }
        .tag-critical, .sev-critical { background-color: #ffdddd; color: #a00; }
        .tag-high, .sev-high { background-color: #ffe8cc; color: #a55; }
        .tag-medium, .sev-medium { background-color: #fff8cc; color: #886400; }
        .tag-low, .sev-low { background-color: #ddffdd; color: #0a5; }
        .tag-info, .sev-info { background-color: #eee; color: #555; }
        .badge-verified { background-color: #ddffdd; }
        .badge-unverified, .badge-failed { background-color: #ffdddd; }
        .footer { color: #888; font-size: 8pt; margin-top: 16px; }
        .chain-summary { font-weight: bold; }
        .filter-bar { display: none; }
        script { display: none; }
    """

    @classmethod
    def _try_xhtml2pdf(cls, html: str, output: Path) -> bool:
        try:
            from xhtml2pdf import pisa  # type: ignore[import-untyped]
        except ImportError:
            return False
        try:
            safe_html = re.sub(r"<script\b.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
            safe_html = re.sub(r"<style\b.*?</style>", f"<style>{cls._PDF_SAFE_CSS}</style>", safe_html,
                                count=1, flags=re.DOTALL | re.IGNORECASE)
            safe_html = re.sub(r"<details\b[^>]*>", '<div class="chain-item">', safe_html, flags=re.IGNORECASE)
            safe_html = re.sub(r"</details>", "</div>", safe_html, flags=re.IGNORECASE)
            safe_html = re.sub(r"<summary\b[^>]*>", '<div class="chain-summary">', safe_html, flags=re.IGNORECASE)
            safe_html = re.sub(r"</summary>", "</div>", safe_html, flags=re.IGNORECASE)

            with open(output, "wb") as f:
                result = pisa.CreatePDF(safe_html, dest=f)
            if result.err:
                print(f"[PDF] xhtml2pdf reported {result.err} error(s)", file=sys.stderr)
                return False
            return output.exists() and output.stat().st_size > 0
        except Exception as exc:
            print(f"[PDF] xhtml2pdf failed: {exc}", file=sys.stderr)
            return False