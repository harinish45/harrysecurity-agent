#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.timeline_analysis
Domain: forensics
Real filesystem timeline: walks a local directory and builds a chronological
timeline from each file's real os.stat() mtime/ctime/atime, and flags a
lightweight anti-forensics heuristic — a file whose metadata-change time
(ctime) clearly postdates its content-modification time (mtime), one shape
"timestomping" can take. Honest-degrades when target isn't a real local
directory.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from typing import Any
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

MAX_FILES = 5000
MAX_TIMELINE_ENTRIES = 500
TIMESTOMP_SKEW_S = 5  # tolerate small clock/filesystem-granularity noise


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def run(target: str, **kwargs: Any) -> dict:
    """Build a real chronological filesystem timeline for a local directory."""
    if not target or not os.path.isdir(target):
        return tool_result(
            "forensics.timeline_analysis", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a real local directory — filesystem timeline analysis requires "
                    "a local directory path, not a network target or a single file.",
            error="target is not a local directory",
        )

    entries: list[dict] = []
    try:
        for root, _dirs, files in os.walk(target):
            for fname in files:
                if len(entries) >= MAX_FILES:
                    break
                fpath = os.path.join(root, fname)
                try:
                    st = os.stat(fpath)
                except OSError:
                    continue
                entries.append({
                    "path": fpath,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "ctime": st.st_ctime,
                    "atime": st.st_atime,
                })
            if len(entries) >= MAX_FILES:
                break
    except OSError as e:
        return tool_result("forensics.timeline_analysis", target, status=STATUS_FAILED, error=str(e))

    entries.sort(key=lambda e: e["mtime"])

    findings = []
    anomalies = []
    for e in entries:
        if e["ctime"] - e["mtime"] > TIMESTOMP_SKEW_S:
            anomalies.append(e["path"])
            findings.append(Finding(
                title="Metadata-change time postdates content-modification time",
                severity="low",
                confidence="low",
                affected_asset=e["path"],
                evidence=f"mtime={_iso(e['mtime'])} but ctime={_iso(e['ctime'])} "
                         f"(ctime is {e['ctime'] - e['mtime']:.1f}s later). One possible cause: "
                         f"metadata/permissions were changed after the content was last written; "
                         f"another is timestamp manipulation ('timestomping').",
                remediation="Correlate with other evidence (access logs, backups) before concluding "
                            "tampering; this heuristic alone is not conclusive.",
                tool="forensics.timeline_analysis",
                references=["MITRE ATT&CK T1070.006"],
            ))

    timeline = [
        {**e, "mtime": _iso(e["mtime"]), "ctime": _iso(e["ctime"]), "atime": _iso(e["atime"])}
        for e in entries[:MAX_TIMELINE_ENTRIES]
    ]

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Built timeline of {len(entries)} file(s); {len(anomalies)} timestamp anomal{'y' if len(anomalies) == 1 else 'ies'} flagged."
    return tool_result(
        "forensics.timeline_analysis", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"file_count": len(entries), "timeline": timeline, "anomalies": anomalies},
    )


tool_registry.register("forensics.timeline_analysis", run, metadata={
    "name": "forensics.timeline_analysis",
    "domain": "forensics",
    "status": "completed",
    "description": "Builds a real chronological filesystem timeline from os.stat mtime/ctime/atime across a local directory, flagging a ctime-after-mtime timestomping heuristic",
    "parameters": {"target": "Path to a local directory"},
})
