#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography.crypto_hash_analysis
Domain: cryptography

Previously byte-for-byte identical to certificate_validation.py,
cryptanalysis.py, key_management.py, and pki_reviews.py (a generic
TLS-socket scan dumping plain strings, unrelated to hashing at all) —
caught during this session's audit.

Now: when `target` is a local file, a real multi-algorithm hash
computation (MD5, SHA-1, SHA-256, SHA3-256) with judged findings that flag
MD5/SHA-1 as cryptographically broken/collision-vulnerable (real,
well-established CVE/CWE-backed guidance, not a network probe at all —
hashing has nothing to do with TLS). When `target` is not a local file,
this honestly reports that hash analysis needs a file to hash rather than
silently reusing an unrelated TLS check.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_OUT_OF_SCOPE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_ALGORITHMS = ("md5", "sha1", "sha256", "sha3_256")
_WEAK_ALGORITHMS = {
    "md5": "MD5 is cryptographically broken — practical collision attacks are well documented (CVE-2004-2761 class).",
    "sha1": "SHA-1 is cryptographically broken — practical collision attacks exist (SHAttered, CVE-2005-4900 class).",
}
_CHUNK_SIZE = 1024 * 1024


def _hash_file(path: str) -> dict[str, str]:
    hashers = {alg: hashlib.new(alg, usedforsecurity=False) if alg == "md5" else hashlib.new(alg) for alg in _ALGORITHMS}
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)
    return {alg: h.hexdigest() for alg, h in hashers.items()}


def run(target: str, **kwargs: Any) -> dict:
    """Real multi-algorithm hash computation for a local file, with weak-algorithm findings."""
    if not os.path.isfile(target):
        return tool_result(
            "cryptography.crypto_hash_analysis", target,
            status=STATUS_OUT_OF_SCOPE,
            summary=f"'{target}' is not a local file — crypto_hash_analysis computes real "
                    f"hashes of a file's contents and needs an actual file path, not a "
                    f"network target",
            error="out_of_scope: target is not a readable local file",
        )

    try:
        digests = _hash_file(target)
        size = os.path.getsize(target)
    except OSError as e:
        return tool_result("cryptography.crypto_hash_analysis", target, status=STATUS_FAILED, error=str(e))

    findings: list[Finding] = [Finding(
        title=f"Computed {len(digests)} hash digest(s) for {os.path.basename(target)}",
        severity="info", confidence="certain",
        affected_asset=target,
        evidence="; ".join(f"{alg.upper()}={digest}" for alg, digest in digests.items()),
        tool="cryptography.crypto_hash_analysis",
    )]

    for alg, note in _WEAK_ALGORITHMS.items():
        findings.append(Finding(
            title=f"{alg.upper()} digest computed but algorithm is cryptographically weak",
            severity="low", confidence="certain",
            affected_asset=target,
            evidence=f"{alg.upper()}={digests[alg]}. {note}",
            remediation="Do not rely on this digest for integrity/security guarantees; use "
                        "SHA-256 or SHA-3 for any security-relevant purpose.",
            tool="cryptography.crypto_hash_analysis",
            references=["CWE-327", "CWE-328"],
        ))

    return tool_result(
        "cryptography.crypto_hash_analysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Hashed {size} byte(s) with {', '.join(a.upper() for a in _ALGORITHMS)}",
        metadata={"file_size": size, "digests": digests},
    )


tool_registry.register("cryptography.crypto_hash_analysis", run, metadata={
    "name": "cryptography.crypto_hash_analysis",
    "domain": "cryptography",
    "status": "completed",
    "description": "Real multi-algorithm file hashing (MD5/SHA-1/SHA-256/SHA3-256) with weak-algorithm collision-risk findings",
    "parameters": {
        "target": "Path to a local file to hash",
    },
})
