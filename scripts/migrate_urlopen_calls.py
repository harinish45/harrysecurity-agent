#!/usr/bin/env python3
"""One-time codemod: route every direct urllib.request.urlopen() call
through nexus.foundation.net.safe_urlopen(), which validates the URL scheme
before opening it (bandit B310 — a file://, ftp://, or other unexpected
scheme reaching urlopen unchecked).

Driven precisely by a bandit B310 JSON report (one file, line-number pair
per finding) rather than a blind whole-file substring search, so nothing
outside what bandit actually flagged as a real urlopen() call gets touched.

Usage: python scripts/migrate_urlopen_calls.py <bandit_report.json>
"""
from __future__ import annotations

import ast
import json
import sys
from collections import defaultdict
from pathlib import Path

OLD_CALL = "urllib.request.urlopen("
NEW_CALL = "safe_urlopen("
IMPORT_LINE = "from nexus.foundation.net import safe_urlopen\n"


def _insert_index(tree: ast.Module, lines: list[str]) -> int:
    """Line index (0-based) to insert the new import at — right after the
    last top-level import statement, or after the module docstring if there
    are none."""
    last_import_line = None
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_import_line = node.end_lineno
        else:
            break  # imports are expected at the top; stop at the first non-import
    if last_import_line is not None:
        return last_import_line

    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
        return tree.body[0].end_lineno

    return 0


def migrate_file(path: Path, line_numbers: set[int]) -> tuple[int, list[str]]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    skipped: list[str] = []
    changed = 0

    for lineno in sorted(line_numbers):
        idx = lineno - 1
        if idx < 0 or idx >= len(lines):
            skipped.append(f"{path}:{lineno}: line number out of range")
            continue
        if OLD_CALL not in lines[idx]:
            skipped.append(f"{path}:{lineno}: expected call not found: {lines[idx].strip()!r}")
            continue
        lines[idx] = lines[idx].replace(OLD_CALL, NEW_CALL)
        changed += 1

    if changed == 0:
        return 0, skipped

    new_text = "".join(lines)
    if IMPORT_LINE not in new_text:
        tree = ast.parse(new_text)
        insert_at = _insert_index(tree, lines)
        lines.insert(insert_at, IMPORT_LINE)
        new_text = "".join(lines)

    path.write_text(new_text, encoding="utf-8")
    return changed, skipped


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python scripts/migrate_urlopen_calls.py <bandit_report.json>")
        sys.exit(1)

    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    by_file: dict[str, set[int]] = defaultdict(set)
    for result in report["results"]:
        if result["test_id"] != "B310":
            continue
        by_file[result["filename"]].add(result["line_number"])

    net_module = (Path(__file__).resolve().parent.parent / "nexus" / "foundation" / "net.py")

    total = 0
    all_skipped: list[str] = []
    for filename, line_numbers in sorted(by_file.items()):
        path = Path(filename)
        if path.resolve() in (Path(__file__).resolve(), net_module):
            continue  # never rewrite this codemod's own file, or safe_urlopen's own definition
        changed, skipped = migrate_file(path, line_numbers)
        total += changed
        all_skipped.extend(skipped)

    print(f"Transformed {total} call site(s) across {len(by_file)} file(s).")
    if all_skipped:
        print(f"\n{len(all_skipped)} site(s) left untouched for manual review:")
        for s in all_skipped:
            print(f"  {s}")


if __name__ == "__main__":
    main()
