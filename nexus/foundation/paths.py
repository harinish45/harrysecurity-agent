"""Traversal-safe path joining.

Several places built a file path directly from user-controlled input —
``REPORTS_DIR / filename`` from a raw URL path parameter (``web/server.py``,
``scripts/serve_reports.py``) — with no check that the result actually stays
under the intended base directory. On Windows, ``pathlib`` treats ``\\`` as
a separator inside what looks like a single URL path segment, so a filename
like ``..\\..\\..\\Windows\\win.ini`` escapes ``REPORTS_DIR`` even though it
contains no ``/``. This is CWE-22.

``safe_join()`` is the one place that resolves a base directory + an
untrusted name and either returns a path guaranteed to be inside that
directory, or raises.
"""
from __future__ import annotations

from pathlib import Path


class PathTraversalError(ValueError):
    pass


def safe_join(base: Path | str, name: str) -> Path:
    """Return ``base / name`` if — and only if — the resolved result is
    still inside ``base``. Raises ``PathTraversalError`` otherwise.

    Rejects outright (before even trying to resolve) any ``name`` containing
    a path separator (``/`` or ``\\``), a null byte, or a leading ``.``
    dot-segment — a legitimate filename served from a flat reports
    directory never needs any of those.
    """
    if not name or not isinstance(name, str):
        raise PathTraversalError("A non-empty filename is required")
    if "\x00" in name:
        raise PathTraversalError("Filename contains a null byte")
    if "/" in name or "\\" in name:
        raise PathTraversalError(f"Filename must not contain a path separator: {name!r}")
    if name in (".", "..") or name.startswith("."):
        raise PathTraversalError(f"Filename must not be a dot-segment: {name!r}")

    base_resolved = Path(base).resolve()
    candidate = (base_resolved / name).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise PathTraversalError(f"{name!r} resolves outside {base_resolved}") from exc
    return candidate


def safe_slug(value: str, *, max_length: int = 120) -> str:
    """Collapse arbitrary text (e.g. a scan target) into a filesystem-safe
    slug: only ``[A-Za-z0-9._-]`` survive, everything else becomes ``_``.
    Stricter than the ``.replace("/", "_").replace(":", "_")`` pattern used
    in a couple of report-naming call sites, which left ``\\`` and ``..``
    sequences untouched."""
    import re

    slug = re.sub(r"[^A-Za-z0-9._-]", "_", value.strip())
    slug = slug.strip("._") or "target"
    return slug[:max_length]
