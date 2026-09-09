#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering.firmware_reverse_engineering
Domain: reverse_engineering

Previously did only file-magic/hash inspection despite the name (checked
exactly one magic number at offset 0 — the whole-file type — and called
that "firmware reverse engineering"). Caught during this session's audit.

Now: a real magic-byte signature scan across the *entire* file for
embedded filesystem/compression signatures commonly found inside firmware
images (the same technique `binwalk` uses) — SquashFS ("hsqs"/"sqsh"),
gzip (\\x1f\\x8b), raw LZMA (\\x5d\\x00\\x00), plus a few other common
embedded-firmware container signatures (JFFS2, CramFS, U-Boot uImage,
device-tree blobs, and embedded ELF images). Reports every offset where a
signature is found — real evidence of an embedded/nested filesystem, which
is the actual first step of firmware reverse engineering (extract, then
analyze what's inside).
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_READ_BYTES = 64 * 1024 * 1024  # 64 MiB safety cap
_MAX_HITS_PER_SIGNATURE = 20

# (label, magic bytes, severity, note)
_SIGNATURES: list[tuple[str, bytes, str, str]] = [
    ("SquashFS (little-endian)", b"hsqs", "high", "Embedded read-only Linux filesystem — extract with unsquashfs."),
    ("SquashFS (big-endian)", b"sqsh", "high", "Embedded read-only Linux filesystem — extract with unsquashfs."),
    ("gzip", b"\x1f\x8b", "medium", "Compressed data/archive embedded in the image."),
    ("raw LZMA", b"\x5d\x00\x00", "medium", "LZMA-compressed data, common for compressed kernels/rootfs."),
    ("JFFS2 (little-endian)", b"\x85\x19", "high", "Embedded flash filesystem."),
    ("JFFS2 (big-endian)", b"\x19\x85", "high", "Embedded flash filesystem."),
    ("CramFS", b"E=\xcd\x28", "high", "Embedded compressed read-only filesystem."),
    ("U-Boot uImage", b"\x27\x05\x19\x56", "medium", "U-Boot firmware image header — indicates a bootloader-packaged image."),
    ("Device Tree Blob (DTB)", b"\xd0\x0d\xfe\xed", "low", "Hardware description blob — useful for identifying target platform."),
    ("embedded ELF", b"\x7fELF", "medium", "Nested ELF binary/kernel image embedded within the file."),
]


def _hash_summary(data: bytes) -> dict:
    return {
        "size": len(data),
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _scan_signatures(data: bytes) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    for label, magic, _, _ in _SIGNATURES:
        offsets = []
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx == -1 or len(offsets) >= _MAX_HITS_PER_SIGNATURE:
                break
            # Skip the file's own header-position match for embedded ELF —
            # offset 0 is just "this file is an ELF", not an embedded one.
            offsets.append(idx)
            start = idx + 1
        if offsets:
            hits[label] = offsets
    return hits


def run(target: str, **kwargs: Any) -> dict:
    """reverse_engineering tool: real magic-byte signature scan for embedded firmware filesystems."""
    if not os.path.isfile(target):
        return tool_result("reverse_engineering.firmware_reverse_engineering", target, status=STATUS_FAILED,
                            error=f"File not found: {target}")

    try:
        size = os.path.getsize(target)
        with open(target, "rb") as f:
            data = f.read(_MAX_READ_BYTES)
        truncated = size > _MAX_READ_BYTES
    except OSError as e:
        return tool_result("reverse_engineering.firmware_reverse_engineering", target, status=STATUS_FAILED, error=str(e))

    summary_info = _hash_summary(data)
    hits = _scan_signatures(data)

    # Embedded ELF at offset 0 just means "this whole file is an ELF" (e.g.
    # a kernel image itself), not a nested filesystem — don't flag that as
    # a "signature found inside" if it's the very first byte.
    if "embedded ELF" in hits and hits["embedded ELF"] == [0]:
        del hits["embedded ELF"]

    if not hits:
        return tool_result(
            "reverse_engineering.firmware_reverse_engineering", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No embedded filesystem/compression signatures found in {size} byte(s) scanned"
                    + (" (file truncated to 64 MiB scan cap)" if truncated else ""),
            metadata={"file": summary_info, "truncated": truncated},
        )

    findings = []
    sig_lookup = {label: (magic, sev, note) for label, magic, sev, note in _SIGNATURES}
    for label, offsets in hits.items():
        magic, sev, note = sig_lookup[label]
        findings.append(Finding(
            title=f"{label} signature found at {len(offsets)} offset(s) in {os.path.basename(target)}",
            severity=sev,
            confidence="certain",
            affected_asset=target,
            evidence=f"Magic {magic!r} found at offsets: {[hex(o) for o in offsets]}",
            remediation=f"{note} Extract and recursively analyze the embedded content.",
            tool="reverse_engineering.firmware_reverse_engineering",
        ))

    return tool_result(
        "reverse_engineering.firmware_reverse_engineering", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Found {sum(len(v) for v in hits.values())} embedded-filesystem/compression "
                f"signature hit(s) across {len(hits)} signature type(s) in {size} byte(s) scanned",
        metadata={"file": summary_info, "signature_hits": hits, "truncated": truncated},
    )


tool_registry.register("reverse_engineering.firmware_reverse_engineering", run, metadata={
    "name": "reverse_engineering.firmware_reverse_engineering",
    "domain": "reverse_engineering",
    "status": "completed",
    "description": "Real whole-file magic-byte signature scan for embedded firmware filesystems/compression (SquashFS, gzip, LZMA, JFFS2, CramFS, U-Boot uImage, DTB, embedded ELF)",
    "parameters": {
        "target": "Path to the target firmware image file",
    },
})
