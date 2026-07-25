#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.log_analysis
Domain: forensics
Structured log analysis with IOC matching, timeline correlation, and pattern detection.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Optional

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry


LOG_PATTERNS = {
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "md5_hash": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "sha1_hash": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "sha256_hash": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "ipv6_address": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "url": re.compile(r"https?://[^\s<>'\"|\\^`\[\]]+"),
    "error": re.compile(r"\b(ERROR|CRITICAL|FATAL|ALERT)\b", re.IGNORECASE),
    "authentication_failure": re.compile(r"\b(authentication failed|login failed|invalid credentials|access denied)\b", re.IGNORECASE),
}

SIEM_FORMATS = ["syslog", "json", "cef", "leef", "windows_event"]


def _parse_log_line(line: str) -> Optional[dict]:
    """Attempt to parse a log line into structured data."""
    line = line.strip()
    if not line:
        return None

    # Try JSON parsing
    if line.startswith("{"):
        try:
            return {"raw": line, "parsed": json.loads(line), "format": "json"}
        except json.JSONDecodeError:
            pass

    # Try syslog pattern
    syslog_match = re.match(r"^<\d+>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.*)$", line)
    if syslog_match:
        return {
            "raw": line,
            "timestamp": syslog_match.group(1),
            "host": syslog_match.group(2),
            "program": syslog_match.group(3),
            "message": syslog_match.group(4),
            "format": "syslog",
        }

    return {"raw": line, "format": "text"}


def _extract_iocs(line: str) -> list[dict]:
    """Extract IOCs from a log line."""
    iocs = []
    for ioc_type, pattern in LOG_PATTERNS.items():
        matches = pattern.findall(line)
        for match in matches:
            iocs.append({"type": ioc_type, "value": match})
    return iocs


def _analyze_log_file(filepath: str, max_lines: int = 10000) -> tuple[list[Finding], list[dict]]:
    """Analyze a log file for security-relevant content."""
    findings = []
    timeline: list[dict] = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break

                parsed = _parse_log_line(line)
                if not parsed:
                    continue

                iocs = _extract_iocs(line)

                if iocs:
                    timeline.append({"line": i + 1, "iocs": iocs, "content": line[:200]})

                for ioc in iocs:
                    if ioc["type"] == "ip_address":
                        findings.append(Finding(
                            title=f"IP address in log at line {i + 1}",
                            severity="info",
                            confidence="high",
                            affected_asset=filepath,
                            evidence=f"IP: {ioc['value']} in {line[:100]}",
                            remediation="Verify if IP is expected in logs.",
                            tool="forensics.log_analysis",
                            references=["CWE-200"],
                        ))
                    elif ioc["type"] == "error":
                        findings.append(Finding(
                            title=f"Error message in log at line {i + 1}",
                            severity="medium",
                            confidence="high",
                            affected_asset=filepath,
                            evidence=f"Error: {ioc['value']} in {line[:100]}",
                            remediation="Investigate error for potential security implications.",
                            tool="forensics.log_analysis",
                        ))
                    elif ioc["type"] == "authentication_failure":
                        findings.append(Finding(
                            title=f"Authentication failure in log at line {i + 1}",
                            severity="high",
                            confidence="certain",
                            affected_asset=filepath,
                            evidence=f"Auth failure: {line[:100]}",
                            remediation="Investigate potential brute force or credential attacks.",
                            tool="forensics.log_analysis",
                            references=["CWE-307", "CWE-798"],
                        ))

    except Exception as e:
        return [Finding(
            title="Log file analysis error",
            severity="low",
            confidence="certain",
            affected_asset=filepath,
            evidence=str(e)[:100],
            remediation="Verify file exists and is readable.",
            tool="forensics.log_analysis",
        )], timeline

    return findings, timeline


def run(
    target: str,
    max_lines: int = 10000,
    check_errors: bool = True,
    check_auth_failures: bool = True,
    output_timeline: bool = True,
    **kwargs: Any,
) -> dict:
    """Perform structured log analysis.

    Parameters
    ----------
    target : str
        Path to log file or directory containing logs.
    max_lines : int
        Maximum lines to analyze per file.
    check_errors : bool
        Flag error-level log messages.
    check_auth_failures : bool
        Flag authentication failures.
    output_timeline : bool
        Return timeline of IOCs found.
    """
    path = target.strip()
    if not path:
        return tool_result("forensics.log_analysis", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    timeline: list[dict] = []

    if not os.path.exists(path):
        return tool_result(
            "forensics.log_analysis", target,
            status=STATUS_NO_FINDINGS,
            error=f"Path not found: {path}",
        )

    files_analyzed = 0

    if os.path.isfile(path):
        file_findings, file_timeline = _analyze_log_file(path, max_lines)
        findings.extend(file_findings)
        timeline.extend(file_timeline)
        files_analyzed = 1
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for fname in files:
                if fname.endswith((".log", ".txt", ".json")):
                    fpath = os.path.join(root, fname)
                    file_findings, file_timeline = _analyze_log_file(fpath, max_lines // 10)
                    findings.extend(file_findings)
                    timeline.extend(file_timeline)
                    files_analyzed += 1
    else:
        return tool_result(
            "forensics.log_analysis", target,
            status=STATUS_FAILED,
            error=f"Invalid target: not a file or directory",
        )

    summary = f"Analyzed {files_analyzed} log file{'s' if files_analyzed > 1 else ''}, found {len(findings)} findings"

    return tool_result(
        "forensics.log_analysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=summary,
        metadata={
            "files_analyzed": files_analyzed,
            "timeline_entries": len(timeline),
            "timeline": timeline[:100] if output_timeline else [],
        },
    )


tool_registry.register("forensics.log_analysis", run, metadata={
    "name": "forensics.log_analysis",
    "domain": "forensics",
    "status": "completed",
    "description": "Structured log analysis with IOC matching and timeline correlation",
    "parameters": {
        "target": "Path to log file or directory",
        "max_lines": "Maximum lines to analyze per file (default: 10000)",
        "check_errors": "Flag error-level log messages (default: True)",
        "check_auth_failures": "Flag authentication failures (default: True)",
        "output_timeline": "Return timeline of IOCs found (default: True)",
    },
})