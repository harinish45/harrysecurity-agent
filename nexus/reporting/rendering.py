"""HTML/CSS-first report rendering with optional WeasyPrint PDF output."""
from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Iterable, Mapping

from .context import ReportContext


def render_html(
    title: str,
    context: ReportContext,
    sections: Iterable[tuple[str, str]],
) -> str:
    body = "\n".join(
        f"<section><h2>{escape(heading)}</h2><div>{content}</div></section>"
        for heading, content in sections
    )
    brand = context.branding
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>{escape(title)}</title>
<style>
:root{{--primary:{escape(brand.primary_color)};--accent:{escape(brand.accent_color)}}}
body{{font-family:Arial,sans-serif;color:#172033;line-height:1.55;margin:48px}}
.cover{{padding:56px 0 34px;border-bottom:4px solid var(--accent)}}
h1{{font-size:34px;margin:8px 0}}h2{{color:var(--primary);border-bottom:1px solid #d9dee7;padding-bottom:6px;margin-top:32px}}
.meta{{color:#5f6b7a}}.confidential{{display:inline-block;padding:5px 9px;border:1px solid var(--accent);font-size:11px;text-transform:uppercase;letter-spacing:.08em}}
section{{break-inside:avoid}}footer{{margin-top:56px;padding-top:12px;border-top:1px solid #d9dee7;color:#657181;font-size:11px}}
</style></head><body>
<div class=\"cover\"><div class=\"confidential\">{escape(brand.footer_text)}</div><h1>{escape(title)}</h1><div class=\"meta\">{escape(brand.organization_name)}</div></div>
{body}
<footer>{escape(brand.organization_name)} · {escape(brand.contact_email)} · Mission {escape(context.provenance.mission_id)}</footer>
</body></html>"""


def render_pdf(html: str, output: str | Path) -> Path:
    """Render HTML to PDF through WeasyPrint when available."""
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise RuntimeError("WeasyPrint is required for PDF rendering") from exc
    HTML(string=html).write_pdf(str(path))
    return path
