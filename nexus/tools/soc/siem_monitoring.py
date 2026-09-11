#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Siem Monitoring
Domain: soc

SIEM monitoring means watching an actual event stream for volume/severity
anomalies over time — it needs a log file with timestamps, not a live
network probe. This previously did a DNS resolve on `target` and GET'd four
hardcoded paths (`/alerts`, `/logs`, `/api/v1/alerts`, `/siem`) against it,
reporting whatever HTTP status came back as "completed" — unrelated to
`target`'s actual log data — caught during this session's audit.

Now: if `target` is a real local log file, this parses Apache/nginx
combined-log or syslog lines, buckets them by minute, and flags a real
statistical volume spike (a minute with a request/event count well above
the file's own mean, via `statistics.mean`/`pstdev`) — the closest
network-agnostic analogue to what a SIEM's rate-based correlation rule
does. It also tallies syslog severity keywords (ERROR/CRITICAL/FAIL/
DENIED) and flags a keyword that dominates the message volume. If `target`
isn't a readable file, it honestly reports STATUS_OUT_OF_SCOPE instead of
fabricating a target assessment from an unrelated HTTP probe.
"""
import os
import re
import statistics
from collections import Counter
from datetime import datetime

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
_SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<proc>[^:\[\s]+)(\[\d+\])?:\s*(?P<msg>.*)$'
)

_SEVERITY_KEYWORDS = ("critical", "error", "fail", "failed", "denied", "warn")

_SPIKE_STDEV_MULTIPLIER = 2.5
_SPIKE_MIN_COUNT = 5


def _read_lines(path: str) -> list:
    lines = []
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= _MAX_LINES:
                break
            lines.append(line.rstrip("\n"))
    return lines


def _apache_minute(ts: str):
    try:
        dt = datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return None


def _syslog_minute(ts: str):
    try:
        dt = datetime.strptime(ts, "%b %d %H:%M:%S")
        return dt.strftime("%m-%d %H:%M")
    except ValueError:
        return None


def run(target: str, **kwargs) -> dict:
    """soc tool: Siem Monitoring"""
    if not os.path.isfile(target):
        return tool_result(
            "soc.siem_monitoring", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"SIEM-style monitoring of {target} requires a real local log file with "
                    f"timestamps — this tool watches event volume/severity over time, it does "
                    f"not probe a network target",
            error="requires_case_data: target is not a readable local file path",
            metadata={"requires": ["a local access-log or syslog file path as `target`"]},
        )

    try:
        size = os.path.getsize(target)
        if size > _MAX_BYTES:
            return tool_result(
                "soc.siem_monitoring", target, status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} is {size} bytes, over this tool's {_MAX_BYTES}-byte cap",
                error="requires_case_data: file too large for inline monitoring",
                metadata={"file_size_bytes": size, "max_bytes": _MAX_BYTES},
            )
        lines = _read_lines(target)
    except OSError as e:
        return tool_result(
            "soc.siem_monitoring", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    minute_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    matched = 0

    for line in lines:
        m = _COMBINED_LOG_RE.match(line)
        if m:
            matched += 1
            bucket = _apache_minute(m.group("ts"))
            if bucket:
                minute_counts[bucket] += 1
            continue
        m2 = _SYSLOG_RE.match(line)
        if m2:
            matched += 1
            bucket = _syslog_minute(m2.group("ts"))
            if bucket:
                minute_counts[bucket] += 1
            msg_lower = m2.group("msg").lower()
            for kw in _SEVERITY_KEYWORDS:
                if kw in msg_lower:
                    severity_counts[kw] += 1
                    break

    if matched == 0:
        return tool_result(
            "soc.siem_monitoring", target, status=STATUS_NO_FINDINGS,
            summary=f"{target} contains {len(lines)} lines but none matched the Apache/nginx "
                    f"combined log or syslog format this monitor needs",
            metadata={"lines_read": len(lines)},
        )

    findings = []
    counts = list(minute_counts.values())
    if len(counts) >= 3:
        mean = statistics.mean(counts)
        stdev = statistics.pstdev(counts)
        threshold = mean + _SPIKE_STDEV_MULTIPLIER * stdev
        for bucket, count in minute_counts.items():
            if count >= _SPIKE_MIN_COUNT and stdev > 0 and count > threshold:
                findings.append(Finding(
                    title=f"Event-volume spike at {bucket}",
                    severity="medium",
                    confidence="medium",
                    affected_asset=target,
                    evidence=f"{count} events in that minute vs. mean {mean:.1f} "
                             f"(stdev {stdev:.1f}) across {len(counts)} minutes",
                    remediation="Investigate what drove the spike — a scan, a DoS attempt, or "
                                "a legitimate traffic burst.",
                ))

    total_severity = sum(severity_counts.values())
    if total_severity:
        top_kw, top_count = severity_counts.most_common(1)[0]
        share = top_count / total_severity
        if share >= 0.5 and top_count >= 5:
            findings.append(Finding(
                title=f"Syslog severity keyword '{top_kw}' dominates message volume",
                severity="medium",
                confidence="medium",
                affected_asset=target,
                evidence=f"'{top_kw}' appeared in {top_count}/{total_severity} "
                         f"severity-tagged messages ({share:.0%})",
                remediation="Investigate the source process(es) emitting these messages.",
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "soc.siem_monitoring", target, status=status, findings=findings,
        summary=f"Monitored {matched}/{len(lines)} parsed events across {len(minute_counts)} "
                f"minute buckets; {len(findings)} anomaly finding(s)",
        metadata={
            "lines_read": len(lines),
            "lines_matched": matched,
            "minute_buckets": len(minute_counts),
            "severity_keyword_counts": dict(severity_counts),
        },
    )


# Register with tool registry
tool_registry.register("soc.siem_monitoring", run, metadata={
    "name": "soc.siem_monitoring",
    "domain": "soc",
    "status": "completed",
    "description": "soc tool: buckets a local log file's events by minute and flags real "
                    "statistical volume spikes and dominant syslog severity keywords; requires "
                    "`target` to be a local log file path, not a network target",
    "parameters": {
        "target": "Local path to a log file to monitor (not a domain/IP/URL)",
    },
})
