"""Risk heatmap visualization — asset x severity grid as inline SVG."""
from __future__ import annotations

from html import escape
from typing import Any

from nexus.foundation.schema import Finding

SVG_WIDTH = 800
SVG_HEIGHT = 500
_LABEL_COL_WIDTH = 180
_HEADER_ROW_HEIGHT = 40
_MARGIN = 20

# Traffic-light severity palette, matching the scale already used elsewhere
# in the reporting layer (see nexus/reporting/generator.py's severity_colors
# and the exporters' sev-* CSS classes).
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}


class RiskHeatmap:
    """Render an asset x severity finding-count grid as an SVG string."""

    def render(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return self._empty_svg("No data")

        columns = list(Finding.SEVERITY_ORDER)
        assets: list[str] = []
        grid: dict[str, dict[str, int]] = {}

        for f in findings:
            asset = str(f.get("affected_asset") or "unknown").strip() or "unknown"
            sev = str(f.get("severity") or "info").lower()
            if sev not in columns:
                sev = "info"
            if asset not in grid:
                grid[asset] = {c: 0 for c in columns}
                assets.append(asset)
            grid[asset][sev] += 1

        if not assets:
            return self._empty_svg("No data")

        rows = len(assets)
        cols = len(columns)
        grid_width = SVG_WIDTH - _LABEL_COL_WIDTH - _MARGIN
        grid_height = SVG_HEIGHT - _HEADER_ROW_HEIGHT - _MARGIN
        cell_w = grid_width / cols
        cell_h = max(20.0, grid_height / max(rows, 1))
        total_height = _HEADER_ROW_HEIGHT + cell_h * rows + _MARGIN

        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SVG_WIDTH} {total_height:.0f}" '
            f'role="img" aria-label="Risk heatmap">',
            f'<rect width="{SVG_WIDTH}" height="{total_height:.0f}" fill="#0a0d14"/>',
        ]

        # Column headers
        for c, sev in enumerate(columns):
            cx = _LABEL_COL_WIDTH + c * cell_w + cell_w / 2
            parts.append(
                f'<text x="{cx:.1f}" y="{_HEADER_ROW_HEIGHT - 12:.1f}" font-size="11" '
                f'fill="#e2e8f0" text-anchor="middle" font-family="monospace">{escape(sev.upper())}</text>'
            )

        # Rows
        for r, asset in enumerate(assets):
            ry = _HEADER_ROW_HEIGHT + r * cell_h
            label = asset if len(asset) <= 24 else asset[:21] + "..."
            parts.append(
                f'<text x="{_LABEL_COL_WIDTH - 10:.1f}" y="{ry + cell_h / 2 + 4:.1f}" font-size="11" '
                f'fill="#e2e8f0" text-anchor="end" font-family="monospace">{escape(label)}</text>'
            )
            for c, sev in enumerate(columns):
                count = grid[asset][sev]
                rx = _LABEL_COL_WIDTH + c * cell_w
                color = SEVERITY_COLORS.get(sev, "#374151")
                opacity = 0.15 if count == 0 else min(1.0, 0.35 + 0.15 * count)
                parts.append(
                    f'<rect x="{rx:.1f}" y="{ry:.1f}" width="{cell_w - 2:.1f}" height="{cell_h - 2:.1f}" '
                    f'fill="{color}" fill-opacity="{opacity:.2f}" stroke="#1e2535"/>'
                )
                if count:
                    parts.append(
                        f'<text x="{rx + cell_w / 2:.1f}" y="{ry + cell_h / 2 + 4:.1f}" font-size="12" '
                        f'fill="#e2e8f0" text-anchor="middle" font-family="monospace">{count}</text>'
                    )

        parts.append('</svg>')
        return "\n".join(parts)

    @staticmethod
    def _empty_svg(message: str) -> str:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
            f'role="img" aria-label="Risk heatmap">'
            f'<rect width="{SVG_WIDTH}" height="{SVG_HEIGHT}" fill="#0a0d14"/>'
            f'<text x="{SVG_WIDTH / 2}" y="{SVG_HEIGHT / 2}" font-size="16" fill="#64748b" '
            f'text-anchor="middle" font-family="sans-serif">{escape(message)}</text>'
            f'</svg>'
        )
