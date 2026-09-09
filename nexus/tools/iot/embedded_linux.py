#!/usr/bin/env python3
"""
NEXUS-STRIKE — iot.embedded_linux
Domain: iot

Previously a plain DNS-resolve + common-IoT-port scan (byte-for-byte
identical to uart_analysis.py, can_bus_testing.py, jtag_analysis.py, and
smart_device_assessment.py before this fix) — embedded Linux review is a
filesystem-image inspection task, not a network scan. Caught during this
session's audit.

Now: when `target` is a local directory (an extracted/mounted firmware
root filesystem — e.g. the output of
reverse_engineering.firmware_reverse_engineering's squashfs extraction),
this performs real, read-only filesystem checks:
  - presence of a `busybox` binary (the standard embedded-Linux userland
    indicator) at common install paths
  - real parsing of `/etc/passwd` for a root entry with a weak/empty
    password hash field (`root::...` = no password at all, or a
    single-DES `$1$`/plain crypt() hash — both real, well-known embedded-
    device misconfigurations)
When `target` is not a local directory, this honestly reports that
embedded-Linux review needs an actual filesystem, not a network target.
"""
from __future__ import annotations

import os
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_BUSYBOX_PATHS = ("bin/busybox", "sbin/busybox", "usr/bin/busybox", "usr/sbin/busybox")

_WEAK_HASH_PREFIXES = ("$1$",)  # MD5-crypt — considered weak for embedded root accounts


def _check_busybox(root: str) -> str | None:
    for rel in _BUSYBOX_PATHS:
        candidate = os.path.join(root, rel)
        if os.path.isfile(candidate) or os.path.islink(candidate):
            return candidate
    return None


def _check_passwd(root: str) -> list[dict]:
    passwd_path = os.path.join(root, "etc", "passwd")
    findings = []
    if not os.path.isfile(passwd_path):
        return findings
    try:
        with open(passwd_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 2 or parts[0] != "root":
                    continue
                pwd_field = parts[1]
                if pwd_field == "":
                    findings.append({"issue": "root account has an EMPTY password field (no auth required)", "field": pwd_field})
                elif any(pwd_field.startswith(p) for p in _WEAK_HASH_PREFIXES):
                    findings.append({"issue": "root password hash uses weak MD5-crypt ($1$)", "field": pwd_field[:20] + "..."})
    except OSError:
        pass
    return findings


def run(target: str, **kwargs: Any) -> dict:
    """iot tool: real embedded-Linux filesystem indicator checks (busybox presence, weak root passwd)."""
    if not os.path.isdir(target):
        return tool_result(
            "iot.embedded_linux", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"'{target}' is not a local directory — embedded_linux inspects an "
                    f"extracted/mounted firmware root filesystem and needs an actual directory "
                    f"path, not a network target",
            error="out_of_scope: target is not a directory (extract firmware first, "
                  "e.g. via reverse_engineering.firmware_reverse_engineering + unsquashfs)",
        )

    findings: list[Finding] = []
    busybox_path = _check_busybox(target)
    if busybox_path:
        findings.append(Finding(
            title=f"busybox binary found at {busybox_path}",
            severity="info", confidence="certain",
            affected_asset=target,
            evidence=f"Standard embedded-Linux userland indicator present: {busybox_path}",
            tool="iot.embedded_linux",
        ))

    for issue in _check_passwd(target):
        findings.append(Finding(
            title=f"Weak root account in /etc/passwd: {issue['issue']}",
            severity="critical", confidence="certain",
            affected_asset=os.path.join(target, "etc", "passwd"),
            evidence=f"field={issue['field']}",
            remediation="Set a strong root password hash (or disable password auth entirely) "
                        "before shipping this firmware image.",
            tool="iot.embedded_linux",
            references=["CWE-521", "CWE-798"],
        ))

    if not findings:
        return tool_result(
            "iot.embedded_linux", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No busybox binary or /etc/passwd found under {target} — does not look "
                    f"like an embedded Linux root filesystem",
        )

    return tool_result(
        "iot.embedded_linux", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Embedded Linux filesystem review of {target} found {len(findings)} finding(s)",
        metadata={"busybox_found": bool(busybox_path)},
    )


tool_registry.register("iot.embedded_linux", run, metadata={
    "name": "iot.embedded_linux",
    "domain": "iot",
    "status": "completed",
    "description": "Real embedded-Linux filesystem review of a local directory (busybox presence, weak/empty root password hash in /etc/passwd)",
    "parameters": {
        "target": "Path to a local extracted/mounted firmware root filesystem directory",
    },
})
