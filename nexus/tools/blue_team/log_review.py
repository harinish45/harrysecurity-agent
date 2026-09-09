#!/usr/bin/env python3
"""
NEXUS-STRIKE — blue_team tool: Log Review
Domain: blue_team

Log review is inherently case-data-based: spotting security-relevant
patterns (an error-rate spike, one IP dominating traffic) requires an
actual log file, not a network probe. This previously ran a bare DNS
resolve + HTTP GET on `/` against `target` and checked for a handful of
security response headers, calling that "log review" — completely
unrelated to logs, always status "completed" — caught during this
session's audit.

Now: if `target` is a real local file path, this does genuine log
parsing — regex-extraction of client IP / timestamp / HTTP status from
Apache/nginx "combined" access-log lines (falling back to syslog-style
lines when the combined format doesn't match), then flags real
statistical anomalies: an elevated 4xx/5xx error rate, and any single IP
responsible for a disproportionate share of requests. If `target` isn't
a readable file, it honestly reports STATUS_OUT_OF_SCOPE instead of
fabricating a target assessment from an unrelated DNS+HTTP check.
"""
import os
import re
from collections import Counter

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_OUT_OF_SCOPE, tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_BYTES = 10 * 1024 * 1024  # 10MB cap so a huge file can't hang the tool
_MAX_LINES = 200_000

_COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
_SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<proc>[^:\[\s]+)(\[\d+\])?:\s*(?P<msg>.*)$'
)


def _read_lines(path: str) -> list:
    lines = []
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= _MAX_LINES:
                break
            lines.append(line.rstrip("\n"))
    return lines


def run(target: str, **kwargs) -> dict:
    """blue_team tool: Log Review"""
    if not os.path.isfile(target):
        return tool_result(
            "blue_team.log_review", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"Log review of {target} requires a real local log file — this tool parses "
                    f"Apache/nginx access-log or syslog lines, it does not probe a network target",
            error="requires_case_data: target is not a readable local file path",
            metadata={"requires": ["a local access-log or syslog file path as `target`"]},
        )

    try:
        size = os.path.getsize(target)
        if size > _MAX_BYTES:
            return tool_result(
                "blue_team.log_review", target,
                status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} is {size} bytes, over this tool's {_MAX_BYTES}-byte review cap",
                error="requires_case_data: file too large for inline review",
                metadata={"file_size_bytes": size, "max_bytes": _MAX_BYTES},
            )
        lines = _read_lines(target)
    except OSError as e:
        return tool_result(
            "blue_team.log_review", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    ip_counter: Counter = Counter()
    status_counter: Counter = Counter()
    combined_matches = 0
    syslog_matches = 0

    for line in lines:
        m = _COMBINED_LOG_RE.match(line)
        if m:
            combined_matches += 1
            ip_counter[m.group("ip")] += 1
            status_counter[m.group("status")] += 1
            continue
        if _SYSLOG_RE.match(line):
            syslog_matches += 1

    total_parsed = combined_matches + syslog_matches
    if total_parsed == 0:
        return tool_result(
            "blue_team.log_review", target, status=STATUS_NO_FINDINGS,
            summary=f"{target} contains {len(lines)} lines but none matched a recognized "
                    f"Apache/nginx combined log or syslog format",
            metadata={"lines_read": len(lines)},
        )

    findings = []
    if combined_matches:
        error_count = sum(c for s, c in status_counter.items() if s.startswith(("4", "5")))
        error_rate = error_count / combined_matches
        if error_rate >= 0.20 and error_count >= 5:
            findings.append(Finding(
                title="Elevated 4xx/5xx error rate in access log",
                severity="medium" if error_rate < 0.5 else "high",
                confidence="high",
                affected_asset=target,
                evidence=f"{error_count}/{combined_matches} requests ({error_rate:.0%}) returned "
                         f"4xx/5xx; breakdown: {dict(status_counter)}",
                remediation="Investigate the source(s) of the elevated error rate — scanning, "
                            "brute-force, or a broken deployment.",
            ))

        if ip_counter:
            top_ip, top_count = ip_counter.most_common(1)[0]
            share = top_count / combined_matches
            if share >= 0.5 and top_count >= 10:
                findings.append(Finding(
                    title=f"Single IP dominates request volume: {top_ip}",
                    severity="medium",
                    confidence="high",
                    affected_asset=target,
                    evidence=f"{top_ip} made {top_count}/{combined_matches} requests "
                             f"({share:.0%} of total)",
                    remediation="Confirm whether this is expected (a load balancer/monitor) or "
                                "abusive traffic warranting a rate limit / block.",
                ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "blue_team.log_review", target, status=status, findings=findings,
        summary=f"Parsed {total_parsed}/{len(lines)} lines ({combined_matches} access-log, "
                f"{syslog_matches} syslog); {len(findings)} anomaly finding(s)",
        metadata={
            "lines_read": len(lines),
            "combined_log_lines_matched": combined_matches,
            "syslog_lines_matched": syslog_matches,
            "status_code_breakdown": dict(status_counter),
            "top_ips": ip_counter.most_common(5),
        },
    )


# Register with tool registry
tool_registry.register("blue_team.log_review", run, metadata={
    "name": "blue_team.log_review",
    "domain": "blue_team",
    "status": "completed",
    "description": "blue_team tool: parses a local Apache/nginx access-log or syslog file for real "
                    "statistical anomalies (error-rate spikes, single-IP volume dominance); "
                    "requires `target` to be a local log file path, not a network target",
    "parameters": {
        "target": "Local path to a log file to review (not a domain/IP/URL)",
    },
})
