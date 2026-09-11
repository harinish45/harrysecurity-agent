"""Structural interface shared by the report exporters.

The exporters (`JsonExport`/`CsvExport`/`HtmlExport`/`SarifExport`/...) have
no common base class — they're independent classes that happen to share an
`export(data, output, redact=True) -> Path` shape. `cli.py`'s
`export-report` command picks one of them at runtime by format string and
calls `.export(...)` on whatever it got; without a declared common type,
that dict is inferred as `dict[str, object]` and mypy correctly flags the
`.export()` call as an error on `object` (a real latent-`AttributeError`
risk if a future exporter class is added without the method). This Protocol
gives that call site a real type without forcing an inheritance change on
every exporter.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ReportExporter(Protocol):
    # Only `data`/`output` are required by every real exporter; the rest of
    # each concrete `export()` differs in name/order (e.g. HtmlExport takes
    # a `title` before `redact`) and are all keyword-defaulted, which the
    # `*args/**kwargs` below models without forcing a stricter positional
    # match than any real call site (cli.py's export-report command) uses.
    def export(self, data: list[Any], output: str | Path, *args: Any, **kwargs: Any) -> Path: ...
