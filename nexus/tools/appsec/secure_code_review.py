#!/usr/bin/env python3
"""
NEXUS-STRIKE — appsec.secure_code_review
Domain: appsec
Real static regex scan of local source files for common anti-patterns:
eval()/exec() on dynamic input, string-concatenated SQL, subprocess calls
with shell=True, and hardcoded password literals.

Previously this ignored `target` as a source path entirely and did a bare
DNS resolve + HTTP GET on "/" (byte-for-byte identical to 19 other stub
tools) — caught during this session's audit. Secure code review is
inherently a local-source-file operation, not a network-observable one;
`target` is now honestly reinterpreted as a local path. A non-local-path
target degrades to STATUS_OUT_OF_SCOPE instead of fabricating results.
"""
from __future__ import annotations

import os
import re
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb", ".go",
    ".cs", ".c", ".cpp", ".h", ".hpp",
}
_EXCLUDED_DIRS = {".git", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
_MAX_FILES_DEFAULT = 500

# (pattern, severity, title, remediation, CWE refs)
_PATTERNS: dict[str, tuple[re.Pattern, str, str, str, list[str]]] = {
    "eval_usage": (
        re.compile(r"\beval\s*\("), "high",
        "Use of eval() on potentially untrusted input",
        "Avoid eval(); use ast.literal_eval() or a proper parser for the data you actually need.",
        ["CWE-95"],
    ),
    "exec_usage": (
        re.compile(r"\bexec\s*\("), "high",
        "Use of exec() on potentially untrusted input",
        "Avoid exec(); refactor to explicit, non-dynamic code paths.",
        ["CWE-95"],
    ),
    "shell_true": (
        re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), "high",
        "subprocess call with shell=True",
        "Call subprocess with a list of arguments and shell=False; never build a shell string from input.",
        ["CWE-78"],
    ),
    "sql_concat": (
        re.compile(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*[\"']\s*\+\s*\w"), "critical",
        "String-concatenated SQL query (possible SQL injection)",
        "Use parameterized queries / prepared statements instead of string concatenation.",
        ["CWE-89"],
    ),
    "hardcoded_password": (
        re.compile(r"(?i)password\s*=\s*[\"'][^\"'\n]{3,}[\"']"), "medium",
        "Hardcoded password literal",
        "Move credentials to environment variables or a secret manager; never commit them in source.",
        ["CWE-798"],
    ),
}


def _scan_file(path: str, tool_name: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                for pattern, severity, title, remediation, refs in _PATTERNS.values():
                    if pattern.search(line):
                        findings.append(Finding(
                            title=title,
                            severity=severity,
                            confidence="medium",
                            affected_asset=path,
                            evidence=f"Line {line_num}: {line.strip()[:160]}",
                            remediation=remediation,
                            tool=tool_name,
                            references=refs,
                        ))
    except OSError:
        pass
    return findings


def _collect_files(path: str, max_files: int) -> list[str]:
    if os.path.isfile(path):
        return [path]
    files: list[str] = []
    for root, dirs, fs in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for fname in fs:
            if os.path.splitext(fname)[1].lower() in _SOURCE_EXTENSIONS:
                files.append(os.path.join(root, fname))
                if len(files) >= max_files:
                    return files
    return files


def run(target: str, max_files: int = _MAX_FILES_DEFAULT, **kwargs: Any) -> dict:
    """Static regex scan of local source files for common security anti-patterns.

    Parameters
    ----------
    target : str
        Path to a source file or a directory tree to scan.
    max_files : int
        Maximum number of source files to scan.
    """
    tool_name = "appsec.secure_code_review"
    path = (target or "").strip()
    if not path:
        return tool_result(tool_name, target, status=STATUS_FAILED, error="Empty target")

    if not os.path.exists(path):
        return tool_result(
            tool_name, target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"{path} is not a local path — secure code review requires local source files, "
                    f"not a network target.",
        )

    files = _collect_files(path, max_files)
    findings: list[Finding] = []
    for f in files:
        findings.extend(_scan_file(f, tool_name))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Static regex scan of {len(files)} source file(s) under {path}: "
                f"{len(findings)} anti-pattern match(es) found.",
        metadata={"files_scanned": len(files), "anti_patterns_found": len(findings)},
    )


tool_registry.register("appsec.secure_code_review", run, metadata={
    "name": "appsec.secure_code_review",
    "domain": "appsec",
    "status": "completed",
    "description": "Real static regex scan of local source files for eval/exec, shell=True subprocess "
                    "calls, string-concatenated SQL, and hardcoded passwords",
    "parameters": {
        "target": "Local path to a source file or directory tree",
        "max_files": f"Maximum source files to scan (default: {_MAX_FILES_DEFAULT})",
    },
})
