#!/usr/bin/env python3
"""
NEXUS-STRIKE — blue_team tool: Hardening
Domain: blue_team

Checking whether a host is hardened means reading its actual configuration
— an SSH daemon config is the canonical example — not probing it over the
network (an open port 22 tells you nothing about `PermitRootLogin`). This
previously did a DNS resolve on `target` and checked a handful of HTTP
security response headers, calling that "hardening" — unrelated to any
host-hardening control — caught during this session's audit.

Now: if `target` is a real local `sshd_config`-style file, this statically
parses its `key value` directives and flags genuine weak settings:
`PermitRootLogin yes`, `PermitEmptyPasswords yes`, `PasswordAuthentication
yes` (key-only auth is the hardened default), `Protocol 1` (obsolete), and
any weak/legacy algorithm named in a `Ciphers`/`MACs`/`KexAlgorithms` line
(CBC-mode ciphers, arcfour, MD5/SHA1-based MACs). If `target` isn't a
readable file, it honestly reports STATUS_OUT_OF_SCOPE instead of
fabricating a target assessment from an unrelated HTTP header check.
"""
import os
import re

from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_OUT_OF_SCOPE, tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_BYTES = 5 * 1024 * 1024

_LINE_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9]*)\s+(.+?)\s*$')

_WEAK_CIPHER_MARKERS = ("cbc", "arcfour", "des", "blowfish", "cast128", "rc4", "none")
_WEAK_MAC_MARKERS = ("md5", "sha1-96", "umac-64", "-96")
_WEAK_KEX_MARKERS = ("diffie-hellman-group1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")


def _parse_sshd_config(text: str) -> dict:
    directives: dict = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        directives.setdefault(key, []).append(value)
    return directives


def _first(directives: dict, key: str):
    for k, values in directives.items():
        if k.lower() == key.lower():
            return values[0]
    return None


def run(target: str, **kwargs) -> dict:
    """blue_team tool: Hardening"""
    if not os.path.isfile(target):
        return tool_result(
            "blue_team.hardening", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"Hardening review of {target} requires the actual host configuration "
                    f"(e.g. an sshd_config) — reachability over the network can't show what "
                    f"`PermitRootLogin` or `PasswordAuthentication` is set to",
            error="requires_case_data: target is not a readable local config file path",
            metadata={"requires": ["a local sshd_config-style file path as `target`"]},
        )

    try:
        if os.path.getsize(target) > _MAX_BYTES:
            return tool_result(
                "blue_team.hardening", target, status=STATUS_OUT_OF_SCOPE,
                summary=f"{target} exceeds this tool's {_MAX_BYTES}-byte review cap",
                error="requires_case_data: file too large for inline review",
            )
        with open(target, "r", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return tool_result(
            "blue_team.hardening", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"Could not read {target}", error=str(e),
        )

    directives = _parse_sshd_config(text)
    if not directives:
        return tool_result(
            "blue_team.hardening", target, status=STATUS_OUT_OF_SCOPE,
            summary=f"{target} doesn't contain any recognizable `Key value` sshd_config "
                    f"directives",
            error="requires_case_data: unrecognized hardening config format",
        )

    findings = []

    root_login = _first(directives, "PermitRootLogin")
    if root_login and root_login.lower() in ("yes", "without-password", "true"):
        findings.append(Finding(
            title="Root login permitted over SSH",
            severity="critical",
            confidence="high",
            evidence=f"PermitRootLogin {root_login}",
            remediation="Set `PermitRootLogin no` and require sudo from a non-root account.",
        ))

    empty_passwords = _first(directives, "PermitEmptyPasswords")
    if empty_passwords and empty_passwords.lower() in ("yes", "true"):
        findings.append(Finding(
            title="Empty passwords permitted",
            severity="critical",
            confidence="high",
            evidence=f"PermitEmptyPasswords {empty_passwords}",
            remediation="Set `PermitEmptyPasswords no`.",
        ))

    password_auth = _first(directives, "PasswordAuthentication")
    if password_auth and password_auth.lower() in ("yes", "true"):
        findings.append(Finding(
            title="Password authentication enabled (key-only is the hardened default)",
            severity="medium",
            confidence="high",
            evidence=f"PasswordAuthentication {password_auth}",
            remediation="Set `PasswordAuthentication no` and enforce public-key authentication.",
        ))

    protocol = _first(directives, "Protocol")
    if protocol and "1" in protocol.split(","):
        findings.append(Finding(
            title="Obsolete SSH protocol version 1 enabled",
            severity="critical",
            confidence="high",
            evidence=f"Protocol {protocol}",
            remediation="Remove protocol version 1; support SSH protocol 2 only.",
        ))

    for key, markers, label in (
        ("Ciphers", _WEAK_CIPHER_MARKERS, "cipher"),
        ("MACs", _WEAK_MAC_MARKERS, "MAC"),
        ("KexAlgorithms", _WEAK_KEX_MARKERS, "key-exchange algorithm"),
    ):
        value = _first(directives, key)
        if not value:
            continue
        algos = [a.strip() for a in value.split(",")]
        weak = [a for a in algos if any(m in a.lower() for m in markers)]
        if weak:
            findings.append(Finding(
                title=f"Weak/legacy {label}(s) configured in {key}",
                severity="medium",
                confidence="high",
                evidence=f"{key} {value} — weak entries: {', '.join(weak)}",
                remediation=f"Remove the weak {label}(s) from `{key}` and restrict to "
                             f"modern algorithms only.",
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        "blue_team.hardening", target, status=status, findings=findings,
        summary=f"Parsed {len(directives)} directive(s) from {target}; "
                f"{len(findings)} hardening issue(s) found",
        metadata={"directives_parsed": len(directives)},
    )


# Register with tool registry
tool_registry.register("blue_team.hardening", run, metadata={
    "name": "blue_team.hardening",
    "domain": "blue_team",
    "status": "completed",
    "description": "blue_team tool: statically analyzes a local sshd_config-style file for "
                    "weak hardening settings (root login, password auth, weak ciphers/MACs); "
                    "requires `target` to be a local config file path, not a network target",
    "parameters": {
        "target": "Local path to an sshd_config-style file (not a domain/IP/URL)",
    },
})
