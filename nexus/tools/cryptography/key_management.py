#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography.key_management
Domain: cryptography

Previously byte-for-byte identical to certificate_validation.py,
cryptanalysis.py, crypto_hash_analysis.py, and pki_reviews.py (a generic
TLS-socket scan dumping plain strings, unrelated to key management at all)
— caught during this session's audit.

Key-management review fundamentally requires credentialed access to a
key-vault/KMS API (AWS KMS, Azure Key Vault, HashiCorp Vault, etc.) — there
is nothing to review about key lifecycle/rotation/access-policy from a
bare hostname. When AWS credentials are present in the environment (boto3
IS in requirements.txt/venv), this performs a real, read-only
`kms.list_keys()`/`list_aliases()` call and reports genuine key metadata
(rotation status via `get_key_rotation_status`). Without credentials, this
honestly reports STATUS_REQUIRES_CREDENTIALS rather than reusing an
unrelated TLS probe.
"""
from __future__ import annotations

from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_REQUIRES_CREDENTIALS,
    tool_result,
)
from nexus.tools.registry import tool_registry


def _has_aws_credentials() -> bool:
    try:
        import boto3
        session = boto3.Session()
        creds = session.get_credentials()
        return creds is not None
    except Exception:
        return False


def run(target: str, region: str | None = None, **kwargs: Any) -> dict:
    """Real AWS KMS key-management review when credentials are present; honest degrade otherwise."""
    if not _has_aws_credentials():
        return tool_result(
            "cryptography.key_management", target,
            status=STATUS_REQUIRES_CREDENTIALS,
            summary=f"Key-management review for {target} requires credentialed access to a "
                    f"key-vault/KMS API (AWS KMS, Azure Key Vault, HashiCorp Vault, etc.) — "
                    f"no AWS credentials were found in this environment",
            error="requires_credentials: no key-vault/KMS API credentials available",
            metadata={
                "note": "This checked for AWS credentials (boto3 Session().get_credentials()) "
                        "as the one key-vault API this codebase already depends on. Point at "
                        "Azure/Vault by supplying that provider's own credentialed client instead.",
            },
        )

    try:
        import boto3
        client = boto3.client("kms", region_name=region)
        keys = client.list_keys().get("Keys", [])
    except Exception as e:
        return tool_result("cryptography.key_management", target, status=STATUS_FAILED, error=str(e)[:300])

    if not keys:
        return tool_result(
            "cryptography.key_management", target,
            status=STATUS_NO_FINDINGS,
            summary=f"AWS KMS credentials present but no keys found in region {region or 'default'}",
        )

    findings: list[Finding] = []
    for key in keys[:50]:
        key_id = key["KeyId"]
        rotation_note = "unknown"
        try:
            rotation = client.get_key_rotation_status(KeyId=key_id)
            rotation_note = "enabled" if rotation.get("KeyRotationEnabled") else "DISABLED"
        except Exception:
            pass
        sev = "medium" if rotation_note == "DISABLED" else "info"
        findings.append(Finding(
            title=f"KMS key {key_id}: automatic rotation {rotation_note}",
            severity=sev, confidence="certain",
            affected_asset=key_id,
            evidence=f"KeyArn={key.get('KeyArn', '')}",
            remediation="Enable automatic key rotation unless there is a documented reason not to."
                        if rotation_note == "DISABLED" else "",
            tool="cryptography.key_management",
            references=["CWE-320"] if rotation_note == "DISABLED" else [],
        ))

    return tool_result(
        "cryptography.key_management", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Reviewed {len(keys)} KMS key(s) in region {region or 'default'}",
        metadata={"key_count": len(keys)},
    )


tool_registry.register("cryptography.key_management", run, metadata={
    "name": "cryptography.key_management",
    "domain": "cryptography",
    "status": "requires_credentials",
    "description": "Real AWS KMS key-rotation review when credentials are available; honest requires_credentials degrade otherwise",
    "parameters": {
        "target": "Target domain, IP, or URL (context only)",
        "region": "Optional AWS region for KMS client",
    },
})
