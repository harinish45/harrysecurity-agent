#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Log Correlation
Domain: soc

Log correlation means tying multiple events from the same source together
to reveal a pattern a single line wouldn't show — brute-forcing, directory
scanning — which needs an actual log file, not a live probe. This
previously did a DNS resolve on `target` and then GET'd four hardcoded
paths (`/alerts`, `/logs`, `/api/v1/alerts`, `/siem`) against it, reporting
whatever HTTP status came back as "completed" — that's a live HTTP probe,
not correlation of anything, and those paths have nothing to do with
`target`'s actual name — caught during this session's audit.

Now: if `target` is a real local access-log file, this groups parsed
requests by client IP and correlates counts within that single grouping to
flag two concrete patterns: (1) an IP responsible for a burst of 401/403
responses (credential/auth brute-forcing), and (2) an IP hitting an
unusually large number of distinct paths dominated by 404s (directory/
endpoint enumeration). If `target` isn't a readable log file, it honestly
reports STATUS_OUT_OF_SCOPE instead of fabricating a target assessment
from an unrelated HTTP probe.
"""
import os
import re
from collections import Counter, defaultdict

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_OUT_OF_SCOPE, tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_BYTES = 10 * 1024 * 1024
_MAX_LINES = 200_000

_COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

# Correlation thresholds
_AUTH_FAIL_THRESHOLD = 5     # 401/403 responses from one IP
_SCAN_DISTINCT_PATH_THRESHOLD = 15   # distinct paths from one IP
_SCAN_404_SHARE = 0.5        # share of those requests that are 404


def _read_lines(path: str) -> list:
    lines = []
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= _MAX_LINES:
                break
            lines.append(line.rstrip("\n"))
    return lines


def run(target: str, **kwargs) -> dict:
    """soc tool: Log Correlation"""
    if not os.path.isfile(target):
        return tool_result(
            "soc.log_correlation", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"Log correlation for {target} requires a real local access-log file — this "
                    f"tool correlates parsed requests by IP, it does not probe a network target",
            error="requires_case_data: target is not a readable local file path",
            metadata={"requires": ["a local access-log file path as `target`"]},
        )

    try:
        size = os.path.getsize(target)
        if size > _MAX_BYTES:
            return tool_result(
                "soc.log_correlation", target, status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} is {size} bytes, over this tool's {_MAX_BYTES}-byte cap",
                error="requires_case_data: file too large for inline correlation",
                metadata={"file_size_bytes": size, "max_bytes": _MAX_BYTES},
            )
        lines = _read_lines(target)
    except OSError as e:
        return tool_result(
            "soc.log_correlation", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    by_ip_status: dict = defaultdict(Counter)
    by_ip_paths: dict = defaultdict(set)
    by_ip_total: Counter = Counter()
    matched = 0

    for line in lines:
        m = _COMBINED_LOG_RE.match(line)
        if not m:
            continue
        matched += 1
        ip = m.group("ip")
        by_ip_status[ip][m.group("status")] += 1
        by_ip_paths[ip].add(m.group("path"))
        by_ip_total[ip] += 1

    if matched == 0:
        return tool_result(
            "soc.log_correlation", target, status=STATUS_NO_FINDINGS,
            summary=f"{target} contains {len(lines)} lines but none matched the Apache/nginx "
                    f"combined log format this correlation needs",
            metadata={"lines_read": len(lines)},
        )

    findings = []
    for ip, statuses in by_ip_status.items():
        auth_fail = statuses.get("401", 0) + statuses.get("403", 0)
        if auth_fail >= _AUTH_FAIL_THRESHOLD:
            findings.append(Finding(
                title=f"Correlated auth-failure burst from {ip}",
                severity="high",
                confidence="high",
                affected_asset=target,
                evidence=f"{ip} produced {auth_fail} correlated 401/403 responses across "
                         f"{by_ip_total[ip]} requests",
                remediation="Investigate for credential brute-forcing from this source; "
                            "consider rate-limiting or blocking.",
            ))

        distinct_paths = len(by_ip_paths[ip])
        not_found = statuses.get("404", 0)
        if distinct_paths >= _SCAN_DISTINCT_PATH_THRESHOLD and by_ip_total[ip] > 0 \
                and (not_found / by_ip_total[ip]) >= _SCAN_404_SHARE:
            findings.append(Finding(
                title=f"Correlated path-enumeration pattern from {ip}",
                severity="medium",
                confidence="medium",
                affected_asset=target,
                evidence=f"{ip} requested {distinct_paths} distinct paths across "
                         f"{by_ip_total[ip]} requests, {not_found} of them 404 "
                         f"({not_found / by_ip_total[ip]:.0%})",
                remediation="Investigate for directory/endpoint enumeration/scanning from "
                            "this source.",
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "soc.log_correlation", target, status=status, findings=findings,
        summary=f"Correlated {matched} access-log lines across {len(by_ip_total)} distinct IPs; "
                f"{len(findings)} correlated pattern(s) found",
        metadata={
            "lines_read": len(lines),
            "lines_matched": matched,
            "distinct_ips": len(by_ip_total),
            "top_ips_by_volume": by_ip_total.most_common(5),
        },
    )


# Register with tool registry
tool_registry.register("soc.log_correlation", run, metadata={
    "name": "soc.log_correlation",
    "domain": "soc",
    "status": "completed",
    "description": "soc tool: correlates parsed requests within a local access-log file by "
                    "source IP to flag auth-failure bursts and path-enumeration patterns; "
                    "requires `target` to be a local log file path, not a network target",
    "parameters": {
        "target": "Local path to an access-log file to correlate (not a domain/IP/URL)",
    },
})
