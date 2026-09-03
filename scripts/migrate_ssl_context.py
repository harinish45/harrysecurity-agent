#!/usr/bin/env python
"""One-time codemod: replace hardcoded ``ssl.CERT_NONE`` blocks with a call
into the centralized, verify-by-default ``get_ssl_context()``.

This script is NOT part of the shipped product — it's a migration tool, run
once, with its output spot-checked by hand. Re-running it after the
migration is a no-op (it only matches the old 3-line pattern).

Pattern matched (indentation-preserving, either ``ctx`` or ``ssl_ctx`` as the
variable name)::

    <ind>X = ssl.create_default_context()
    <ind>X.check_hostname = False
    <ind>X.verify_mode = ssl.CERT_NONE

Replaced with::

    <ind>X = get_ssl_context(<target_expr>, allow_insecure=True)

``<target_expr>`` is inferred from the nearest enclosing function's
parameter list (preferring ``target``, then ``host``, ``hostname``, ``url``,
``domain``, ``ip``). Files where no such parameter is found are left
untouched and reported for manual follow-up rather than guessed at.

Usage:
    python scripts/migrate_ssl_context.py            # apply
    python scripts/migrate_ssl_context.py --dry-run  # report only
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PATTERN = re.compile(
    r"(?P<indent>[ \t]*)(?P<var>\w+)\s*=\s*ssl\.create_default_context\(\)\n"
    r"(?P=indent)(?P=var)\.check_hostname\s*=\s*False\n"
    r"(?P=indent)(?P=var)\.verify_mode\s*=\s*ssl\.CERT_NONE\n?",
)

DEF_START_RE = re.compile(r"^([ \t]*)(?:async\s+)?def\s+\w+\s*\(", re.MULTILINE)
ASSIGN_RE = re.compile(r"^[ \t]*(?P<name>\w+)\s*=[^=]")
PARAM_PRIORITY = ["target", "host", "hostname", "url", "domain", "ip", "address"]

SKIP_FILES = {"scripts/migrate_ssl_context.py", "scripts/_fix_recon_stubs.py"}


def _param_names(params_src: str) -> list[str]:
    names = []
    for raw in params_src.split(","):
        raw = raw.strip()
        if not raw or raw in ("self", "cls") or raw.startswith("*"):
            continue
        name = raw.split(":")[0].split("=")[0].strip()
        if name.isidentifier():
            names.append(name)
    return names


def _function_frames(text: str) -> list[tuple[int, int, int, list[str]]]:
    """All function headers in ``text`` as ``(indent, start_line, end_line,
    params)``, ``end_line`` being the 0-indexed line the header's closing
    ``):`` (or ``) -> Ret:``) lands on. Uses manual paren-depth counting so
    multi-line signatures — common in this codebase — resolve correctly,
    unlike a single-line regex."""
    frames = []
    for m in DEF_START_RE.finditer(text):
        indent = len(m.group(1))
        depth = 1
        i = m.end()
        while i < len(text) and depth > 0:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        params_text = text[m.end():i - 1]
        colon_idx = text.find(":", i)
        start_line = text.count("\n", 0, m.start())
        end_line = text.count("\n", 0, colon_idx) if colon_idx != -1 else start_line
        frames.append((indent, start_line, end_line, _param_names(params_text)))
    return frames


def _enclosing_target_param(text: str, match_start: int, match_indent: int) -> str | None:
    """A target-like expression in scope at ``match_start``: prefer a
    parameter of the innermost *enclosing* ``def`` (tracked via an
    indentation stack of function frames — including ones with multi-line
    signatures — so a sibling helper defined earlier in the same outer
    function doesn't get mistaken for the enclosing scope); fall back to the
    most recent local-variable assignment (e.g. ``url = f"https://{bucket}
    ..."``) since the innermost def's body started. Both are searched in
    PARAM_PRIORITY order. Returns None — callers must not guess — if
    neither yields a hit."""
    match_line_no = text.count("\n", 0, match_start)
    lines = text.splitlines()
    frames = sorted(_function_frames(text), key=lambda f: f[2])  # by end_line
    frame_idx = 0

    stack: list[tuple[int, list[str], int]] = []  # (indent, params, body_start_line)
    for i, line in enumerate(lines[:match_line_no]):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            indent = len(line) - len(line.lstrip(" \t"))
            while stack and indent <= stack[-1][0]:
                stack.pop()
        while frame_idx < len(frames) and frames[frame_idx][2] == i:
            _, _, _, params = frames[frame_idx]
            frame_indent = frames[frame_idx][0]
            stack.append((frame_indent, params, i + 1))
            frame_idx += 1

    while stack and match_indent <= stack[-1][0]:
        stack.pop()

    if not stack:
        return None
    _, nearest_params, def_line_no = stack[-1]

    for pref in PARAM_PRIORITY:
        if pref in nearest_params:
            return pref

    assigned: set[str] = set()
    for line in lines[def_line_no + 1:match_line_no]:
        am = ASSIGN_RE.match(line)
        if am:
            assigned.add(am.group("name"))
    for pref in PARAM_PRIORITY:
        if pref in assigned:
            return pref
    return None


def _has_import(text: str) -> bool:
    return "from nexus.foundation.ssl_config import get_ssl_context" in text


def _add_import(text: str) -> str:
    """Insert the get_ssl_context import after: any leading '#'-prefixed
    lines (shebang, coding cookie, ...), the module docstring (if any), and
    the whole top-of-file import block — INCLUDING parenthesized multi-line
    `from x import (\n  a,\n  b,\n)` statements, which a naive per-line scan
    would insert into the middle of."""
    lines = text.splitlines(keepends=True)

    i = 0
    while i < len(lines) and lines[i].lstrip().startswith("#"):
        i += 1

    if i < len(lines) and (lines[i].lstrip().startswith('"""') or lines[i].lstrip().startswith("'''")):
        quote = lines[i].lstrip()[:3]
        rest_after_open = lines[i].lstrip()[3:]
        if quote in rest_after_open:
            i += 1
        else:
            i += 1
            while i < len(lines) and quote not in lines[i]:
                i += 1
            if i < len(lines):
                i += 1

    insert_at = i
    j = i
    while j < len(lines):
        stripped = lines[j].strip()
        if stripped.startswith(("import ", "from ")):
            depth = lines[j].count("(") - lines[j].count(")")
            k = j
            while depth > 0 and k + 1 < len(lines):
                k += 1
                depth += lines[k].count("(") - lines[k].count(")")
            insert_at = k + 1
            j = k + 1
        elif stripped == "":
            j += 1
        else:
            break

    lines.insert(insert_at, "from nexus.foundation.ssl_config import get_ssl_context\n")
    return "".join(lines)


def migrate_file(path: Path, dry_run: bool) -> tuple[int, bool]:
    text = path.read_text(encoding="utf-8")
    matches = list(PATTERN.finditer(text))
    if not matches:
        return 0, False

    replaced = 0
    unresolved = 0
    out = []
    last_end = 0
    for m in matches:
        param = _enclosing_target_param(text, m.start(), len(m.group("indent")))
        out.append(text[last_end:m.start()])
        indent = m.group("indent")
        var = m.group("var")
        if param is None:
            unresolved += 1
            out.append(text[m.start():m.end()])  # leave unresolved matches untouched
        else:
            out.append(f"{indent}{var} = get_ssl_context({param}, allow_insecure=True)\n")
            replaced += 1
        last_end = m.end()
    out.append(text[last_end:])
    new_text = "".join(out)

    if replaced and not _has_import(new_text):
        new_text = _add_import(new_text)

    if not dry_run and replaced:
        path.write_text(new_text, encoding="utf-8")

    if unresolved:
        print(f"  ! {path.relative_to(REPO_ROOT)}: {unresolved} block(s) left unresolved (no target param found)")
    return replaced, unresolved > 0


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    total_replaced = 0
    total_files = 0
    flagged_files = 0
    for path in sorted(REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in SKIP_FILES or "/.venv/" in f"/{rel}" or rel.startswith(".venv/"):
            continue
        replaced, has_unresolved = migrate_file(path, dry_run)
        if replaced:
            total_files += 1
            total_replaced += replaced
        if has_unresolved:
            flagged_files += 1

    verb = "Would migrate" if dry_run else "Migrated"
    print(f"\n{verb} {total_replaced} SSL context block(s) across {total_files} file(s).")
    if flagged_files:
        print(f"{flagged_files} file(s) have blocks needing manual review (see '!' lines above).")


if __name__ == "__main__":
    main()
