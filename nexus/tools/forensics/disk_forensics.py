#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.disk_forensics
Domain: forensics
Real partition-table / filesystem-signature check on a local disk-image
file: MBR boot signature (0x55AA at byte offset 510), GPT header
("EFI PART" at LBA1 / byte offset 512), and common filesystem magic bytes
(NTFS OEM ID, ext2/3/4 superblock magic, FAT type strings) — all via stdlib
`struct`, no third-party disk-forensics library. Honest-degrades when target
isn't a readable local file (or is too small to hold a boot sector).
"""
from __future__ import annotations
import os
import struct
from typing import Any, Optional
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

READ_SIZE = 2 * 1024 * 1024


def _check_mbr(data: bytes) -> bool:
    return len(data) >= 512 and data[510:512] == b"\x55\xaa"


def _check_gpt(data: bytes) -> bool:
    return len(data) >= 520 and data[512:520] == b"EFI PART"


def _check_ntfs(data: bytes) -> bool:
    return len(data) >= 11 and data[3:11] == b"NTFS    "


def _check_fat(data: bytes) -> Optional[str]:
    if len(data) < 90:
        return None
    for label, offset in (("FAT32", 82), ("FAT16", 54), ("FAT12", 54)):
        chunk = data[offset:offset + 8]
        if chunk.startswith(label.encode()):
            return label
    return None


def _check_ext(data: bytes) -> bool:
    # ext2/3/4 superblock starts at absolute byte offset 1024; the magic
    # (0xEF53, little-endian uint16) sits at superblock offset 56, i.e.
    # absolute offset 1080.
    if len(data) < 1082:
        return False
    magic = struct.unpack_from("<H", data, 1080)[0]
    return magic == 0xEF53


def run(target: str, **kwargs: Any) -> dict:
    """Check a local disk-image file for partition-table and filesystem magic bytes."""
    if not target or not os.path.isfile(target):
        return tool_result(
            "forensics.disk_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a readable local file — disk forensics requires a local "
                    "disk-image file path, not a network target.",
            error="target is not a local file",
        )

    try:
        with open(target, "rb") as f:
            data = f.read(READ_SIZE)
    except OSError as e:
        return tool_result("forensics.disk_forensics", target, status=STATUS_FAILED, error=str(e))

    if len(data) < 512:
        return tool_result(
            "forensics.disk_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary=f"File is only {len(data)} bytes — too small to contain a partition table/boot sector.",
            error="file too small",
        )

    findings = []
    detected = []

    if _check_mbr(data):
        detected.append("mbr")
        findings.append(Finding(
            title="MBR boot signature found",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence="Bytes at offset 510-511 are 0x55 0xAA (the standard MBR boot-sector signature).",
            remediation="Parse the MBR partition entries (offsets 446-509) to enumerate partitions.",
            tool="forensics.disk_forensics",
        ))

    if _check_gpt(data):
        detected.append("gpt")
        findings.append(Finding(
            title="GPT header found",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence="Bytes at offset 512-519 are 'EFI PART' (GPT header signature at LBA1).",
            remediation="Parse the GPT header/partition-entry array for full partition layout.",
            tool="forensics.disk_forensics",
        ))

    if _check_ntfs(data):
        detected.append("ntfs")
        findings.append(Finding(
            title="NTFS filesystem signature found",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence="Bytes at offset 3-10 are 'NTFS    ' (NTFS boot-sector OEM ID).",
            remediation="Use an NTFS-aware forensic tool (e.g. The Sleuth Kit) for full filesystem parsing.",
            tool="forensics.disk_forensics",
        ))

    fat_label = _check_fat(data)
    if fat_label:
        detected.append(fat_label.lower())
        findings.append(Finding(
            title=f"{fat_label} filesystem signature found",
            severity="info",
            confidence="medium",
            affected_asset=target,
            evidence=f"Boot-sector bytes match the '{fat_label}' filesystem-type string.",
            remediation="Use a FAT-aware forensic tool for full filesystem parsing.",
            tool="forensics.disk_forensics",
        ))

    if _check_ext(data):
        detected.append("ext2/3/4")
        findings.append(Finding(
            title="ext2/3/4 superblock magic found",
            severity="info",
            confidence="high",
            affected_asset=target,
            evidence="uint16 at byte offset 1080 (superblock offset 56) is 0xEF53, the ext2/3/4 magic number.",
            remediation="Use an ext-aware forensic tool (e.g. The Sleuth Kit) to parse the superblock and inode tables.",
            tool="forensics.disk_forensics",
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = (
        f"Checked {len(data)} bytes; detected: "
        f"{', '.join(detected) if detected else 'no recognized partition table/filesystem signature'}."
    )
    return tool_result(
        "forensics.disk_forensics", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"bytes_checked": len(data), "detected": detected},
    )


tool_registry.register("forensics.disk_forensics", run, metadata={
    "name": "forensics.disk_forensics",
    "domain": "forensics",
    "status": "completed",
    "description": "Checks a local disk-image file for MBR/GPT partition-table signatures and NTFS/FAT/ext filesystem magic bytes via stdlib struct",
    "parameters": {"target": "Path to a local disk-image file"},
})
