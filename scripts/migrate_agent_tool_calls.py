#!/usr/bin/env python3
"""One-time codemod: route agent tool calls through the guardrailed
tool_registry.run() instead of the raw, guardrail-bypassing tool_registry.get().

Before:
    tool_fn = tool_registry.get(tool_name)
    result = tool_fn(target=target)

After:
    result = tool_registry.run(tool_name, target=target)

Only transforms the exact two-line adjacent pattern (get-then-call on the very
next non-blank line, with the get-assigned variable used nowhere else in
between). Anything that doesn't match exactly is left untouched and reported
so it can be reviewed by hand.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

GET_RE = re.compile(r"^(?P<indent>\s*)(?P<var>\w+)\s*=\s*tool_registry\.get\((?P<expr>.*)\)\s*$")


def _call_re(var: str) -> re.Pattern:
    return re.compile(
        rf"^(?P<indent>\s*)(?P<result>\w+)\s*=\s*{re.escape(var)}\((?P<kwargs>.*)\)\s*$"
    )


def migrate_file(path: Path) -> tuple[int, list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    out: list[str] = []
    skipped: list[str] = []
    changed = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        m = GET_RE.match(line.rstrip("\n"))
        if not m:
            out.append(line)
            i += 1
            continue

        var = m.group("var")
        expr = m.group("expr")
        indent = m.group("indent")

        # Find the next non-blank line — must be the call, adjacent.
        if i + 1 >= len(lines):
            out.append(line)
            skipped.append(f"{path}:{i+1}: get() is last line in file")
            i += 1
            continue

        next_line = lines[i + 1]
        call_m = _call_re(var).match(next_line.rstrip("\n"))
        if not call_m or call_m.group("indent") != indent:
            out.append(line)
            skipped.append(f"{path}:{i+1}: no adjacent `{var}(...)` call on next line")
            i += 1
            continue

        kwargs = call_m.group("kwargs")
        if "target" not in kwargs:
            out.append(line)
            skipped.append(f"{path}:{i+1}: call has no target= kwarg: {next_line.strip()!r}")
            i += 1
            continue

        result = call_m.group("result")
        newline = "\n" if line.endswith("\n") else ""
        out.append(f"{indent}{result} = tool_registry.run({expr}, {kwargs}){newline}")
        changed += 1
        i += 2  # consumed both lines

    if changed:
        path.write_text("".join(out), encoding="utf-8")
    return changed, skipped


def main() -> None:
    root = Path(__file__).resolve().parent.parent / "nexus" / "agents"
    total = 0
    all_skipped: list[str] = []
    for path in sorted(root.rglob("*.py")):
        changed, skipped = migrate_file(path)
        total += changed
        all_skipped.extend(skipped)

    print(f"Transformed {total} call site(s).")
    if all_skipped:
        print(f"\n{len(all_skipped)} site(s) left untouched for manual review:")
        for s in all_skipped:
            print(f"  {s}")


if __name__ == "__main__":
    sys.exit(main())
