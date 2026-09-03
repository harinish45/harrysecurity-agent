"""Finding timeline visualization — horizontal inline SVG timeline."""
from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

SVG_WIDTH = 800
SVG_HEIGHT = 220
_MARGIN = 60
_AXIS_Y = SVG_HEIGHT / 2

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}


class TimelineViz:
    """Render findings as a horizontal, time-ordered SVG timeline."""

    def render(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return self._empty_svg("No data")

        dated = []
        for f in findings:
            ts = self._parse_timestamp(f.get("timestamp"))
            if ts is not None:
                dated.append((ts, f))

        if not dated:
            return self._empty_svg("No data")

        dated.sort(key=lambda pair: pair[0])

        t_min = dated[0][0]
        t_max = dated[-1][0]
        span = (t_max - t_min).total_seconds() or 1.0
        usable_width = SVG_WIDTH - 2 * _MARGIN
        single_point = len(dated) == 1

        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
            f'role="img" aria-label="Finding timeline">',
            f'<rect width="{SVG_WIDTH}" height="{SVG_HEIGHT}" fill="#0a0d14"/>',
            f'<line x1="{_MARGIN}" y1="{_AXIS_Y}" x2="{SVG_WIDTH - _MARGIN}" y2="{_AXIS_Y}" '
            f'stroke="#334155" stroke-width="2"/>',
        ]

        for i, (ts, f) in enumerate(dated):
            if single_point:
                x = SVG_WIDTH / 2
            else:
                x = _MARGIN + (ts - t_min).total_seconds() / span * usable_width
            sev = str(f.get("severity") or "info").lower()
            color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
            y = _AXIS_Y - 18 if i % 2 == 0 else _AXIS_Y + 18
            title = str(f.get("title") or "")
            label = title if len(title) <= 20 else title[:17] + "..."

            parts.append(
                f'<line x1="{x:.1f}" y1="{_AXIS_Y}" x2="{x:.1f}" y2="{y:.1f}" stroke="#1e2535"/>'
            )
            parts.append(
                f'<circle cx="{x:.1f}" cy="{_AXIS_Y}" r="7" fill="{color}" '
                f'stroke="#0a0d14" stroke-width="1.5">'
                f'<title>{escape(label)} ({escape(sev)})</title></circle>'
            )
            text_anchor_y = y - 6 if i % 2 == 0 else y + 14
            parts.append(
                f'<text x="{x:.1f}" y="{text_anchor_y:.1f}" font-size="9" fill="#e2e8f0" '
                f'text-anchor="middle" font-family="monospace">{escape(label)}</text>'
            )

        parts.append('</svg>')
        return "\n".join(parts)

    @staticmethod
    def _parse_timestamp(value: Any):
        if not value or not isinstance(value, str):
            return None
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    @staticmethod
    def _empty_svg(message: str) -> str:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" '
            f'role="img" aria-label="Finding timeline">'
            f'<rect width="{SVG_WIDTH}" height="{SVG_HEIGHT}" fill="#0a0d14"/>'
            f'<text x="{SVG_WIDTH / 2}" y="{SVG_HEIGHT / 2}" font-size="16" fill="#64748b" '
            f'text-anchor="middle" font-family="sans-serif">{escape(message)}</text>'
            f'</svg>'
        )
