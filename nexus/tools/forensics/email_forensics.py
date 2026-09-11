#!/usr/bin/env python3
"""
NEXUS-STRIKE — forensics.email_forensics
Domain: forensics
Real email parsing via the stdlib `email`/`mailbox` modules: headers,
sender/recipient, SPF/DKIM/DMARC authentication-header presence, and
attachment listing for a local `.eml` file (or every message in an mbox
file). Honest-degrades when target isn't a readable local file that
actually parses into a message with at least one recognizable header.
"""
from __future__ import annotations
import mailbox
import os
from email import policy
from email.parser import BytesParser
from typing import Any
from nexus.foundation.schema import (
    Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result,
)
from nexus.tools.registry import tool_registry

AUTH_HEADERS = ["Received-SPF", "DKIM-Signature", "Authentication-Results", "ARC-Authentication-Results"]
MAX_MESSAGES = 200


def _extract(msg) -> dict:
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
            })

    present_auth_headers = [h for h in AUTH_HEADERS if msg.get(h) is not None]

    return {
        "subject": msg.get("Subject", "") or "",
        "from": msg.get("From", "") or "",
        "to": msg.get("To", "") or "",
        "cc": msg.get("Cc", "") or "",
        "date": msg.get("Date", "") or "",
        "message_id": msg.get("Message-ID", "") or "",
        "auth_headers_present": present_auth_headers,
        "attachments": attachments,
    }


def run(target: str, **kwargs: Any) -> dict:
    """Parse a local .eml/mbox file for headers, auth-header presence, and attachments."""
    if not target or not os.path.isfile(target):
        return tool_result(
            "forensics.email_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary="Target is not a readable local file — email forensics requires a local "
                    ".eml or mbox file path, not a network target.",
            error="target is not a local file",
        )

    try:
        with open(target, "rb") as f:
            raw = f.read()
    except OSError as e:
        return tool_result("forensics.email_forensics", target, status=STATUS_FAILED, error=str(e))

    is_mbox = raw.startswith(b"From ") or target.lower().endswith(".mbox")

    try:
        if is_mbox:
            box = mailbox.mbox(target)
            messages = [_extract(m) for m in list(box)[:MAX_MESSAGES]]
        else:
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            messages = [_extract(msg)]
    except Exception as e:
        return tool_result(
            "forensics.email_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary=f"File does not parse as a valid email/mbox message: {e}",
            error=str(e),
        )

    # email.parser is lenient and will "succeed" on arbitrary text; require
    # at least one recognizable header before treating this as a real
    # message, so honest-degrade doesn't false-positive to "completed".
    has_headers = any(m["from"] or m["subject"] or m["to"] or m["message_id"] for m in messages)
    if not has_headers:
        return tool_result(
            "forensics.email_forensics", target,
            status=STATUS_UNAVAILABLE,
            summary="File parsed but contains no recognizable email headers "
                    "(From/To/Subject/Message-ID) — not a real .eml/mbox message.",
            error="no recognizable email headers",
        )

    findings = []
    for m in messages:
        if not m["auth_headers_present"]:
            findings.append(Finding(
                title="No SPF/DKIM/DMARC authentication headers present",
                severity="medium",
                confidence="high",
                affected_asset=target,
                evidence=f"Message from '{m['from']}' has none of {AUTH_HEADERS} — sender "
                         f"authenticity cannot be verified from this message alone.",
                remediation="Treat sender identity as unverified; check the receiving mail server's "
                            "raw logs for the actual SPF/DKIM/DMARC evaluation result.",
                tool="forensics.email_forensics",
                references=["CWE-290", "MITRE ATT&CK T1566"],
            ))
        if m["attachments"]:
            findings.append(Finding(
                title=f"Email contains {len(m['attachments'])} attachment(s)",
                severity="info",
                confidence="certain",
                affected_asset=target,
                evidence=f"Attachments: {[a['filename'] for a in m['attachments']]}",
                remediation="Scan attachments for malware before opening.",
                tool="forensics.email_forensics",
            ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Parsed {len(messages)} message(s) from {'mbox' if is_mbox else 'eml'} file; {len(findings)} finding(s)."
    return tool_result(
        "forensics.email_forensics", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"format": "mbox" if is_mbox else "eml", "messages": messages},
    )


tool_registry.register("forensics.email_forensics", run, metadata={
    "name": "forensics.email_forensics",
    "domain": "forensics",
    "status": "completed",
    "description": "Parses a local .eml/mbox email file for headers, sender/recipient, SPF/DKIM/DMARC header presence, and attachment listing",
    "parameters": {"target": "Path to a local .eml or mbox file"},
})
