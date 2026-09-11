#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.deleted_file_recovery
Domain: forensics
Real basic file carving: scans the raw bytes of a local disk-image/raw file
for common file-signature ("magic bytes") patterns (JPEG, PDF, ZIP, GIF,
PNG) and reports their real byte offsets, bounded to the first N MB. This is
signature-only carving (no filesystem/allocation-table awareness — it can
find embedded/deleted-file fragments a filesystem-aware tool would miss, but
can also over-report signature bytes that occur incidentally inside
unrelated data). Honest-degrades when target isn't a readable local file.
"""
from __future__ import annotations
import os
from typing import Any
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

MAX_SCAN_BYTES = 50 * 1024 * 1024  # bound to first 50MB
MAX_HITS_PER_TYPE = 100

SIGNATURES = {
    "jpeg": b"\xff\xd8\xff",
    "pdf": b"%PDF",
    "zip": b"PK\x03\x04",
    "gif": b"GIF8",
    "png": b"\x89PNG\r\n\x1a\n",
}


def _carve(data: bytes) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    for name, sig in SIGNATURES.items():
        offsets = []
        start = 0
        while len(offsets) < MAX_HITS_PER_TYPE:
            idx = data.find(sig, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        if offsets:
            hits[name] = offsets
    return hits


def run(target: str, **kwargs: Any) -> dict:
    """Carve embedded/deleted file fragments out of a local disk-image/raw file by magic bytes."""
    if not target or not os.path.isfile(target):
        return tool_result(
            "forensics.deleted_file_recovery", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a readable local file — deleted-file recovery requires a local "
                    "disk-image or raw-dump file path, not a network target.",
            error="target is not a local file",
        )

    try:
        with open(target, "rb") as f:
            data = f.read(MAX_SCAN_BYTES)
    except OSError as e:
        return tool_result("forensics.deleted_file_recovery", target, status=STATUS_FAILED, error=str(e))

    hits = _carve(data)
    findings = []
    for ftype, offsets in hits.items():
        findings.append(Finding(
            title=f"Carved {ftype.upper()} file signature(s)",
            severity="info",
            confidence="medium",
            affected_asset=target,
            evidence=f"Found {len(offsets)} {ftype.upper()} signature match(es) at byte offset(s) "
                     f"{offsets[:20]}{'...' if len(offsets) > 20 else ''} (magic bytes {SIGNATURES[ftype]!r}). "
                     f"Signature-based carving; not filesystem-aware, so offsets may include false positives.",
            remediation="Extract and validate candidate regions with a filesystem-aware carving tool "
                        "(e.g. Scalpel, PhotoRec) before treating as recovered evidence.",
            tool="forensics.deleted_file_recovery",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    total_hits = sum(len(v) for v in hits.values())
    summary = f"Scanned {len(data)} bytes; carved {total_hits} file-signature match(es) across {len(hits)} type(s)."
    return tool_result(
        "forensics.deleted_file_recovery", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"bytes_scanned": len(data), "hits_by_type": hits},
    )


tool_registry.register("forensics.deleted_file_recovery", run, metadata={
    "name": "forensics.deleted_file_recovery",
    "domain": "forensics",
    "status": "completed",
    "description": "Basic magic-byte file carving over a local disk-image/raw file (JPEG/PDF/ZIP/GIF/PNG), reporting real byte offsets",
    "parameters": {"target": "Path to a local disk-image or raw-dump file"},
})
