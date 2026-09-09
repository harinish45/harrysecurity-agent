#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.smb_enum
Domain: network

Previously a plain generic port sweep (byte-for-byte identical to
nfs_enum.py, snmp_enum.py, etc. before this fix) — it never spoke SMB at
all. Caught during this session's audit.

Now: a real SMB2 NEGOTIATE request (the same first packet every SMB
client — Windows, smbclient, Impacket — sends) to port 445/tcp, parsing
the response's protocol signature and negotiated dialect. If `smbclient`
is available on PATH, `smbclient -L` (unauthenticated share listing) is
used as a real, standard bonus enumeration step.
"""
from __future__ import annotations

import shutil
import socket
import struct
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.tools.sandbox import SandboxError, run_subprocess

_SMB_PORT = 445

_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
    0x02FF: "SMB2 wildcard (multi-protocol negotiate)",
}


def _build_smb2_negotiate_request(message_id: int = 0) -> bytes:
    """Build a real SMB2 NEGOTIATE_REQUEST packet (MS-SMB2 2.2.3) wrapped in
    NetBIOS Session Service framing, offering the SMB 2.0.2 dialect — the
    minimal, unauthenticated first packet of every SMB2 session."""
    protocol_id = b"\xfeSMB"
    smb2_header = (
        protocol_id +
        struct.pack("<H", 64) +   # StructureSize
        struct.pack("<H", 0) +    # CreditCharge
        struct.pack("<H", 0) +    # (ChannelSequence/Reserved as Status hi for req) — Status
        struct.pack("<H", 0) +    # Command = SMB2 NEGOTIATE (0x0000)
        struct.pack("<H", 1) +    # CreditRequest
        struct.pack("<I", 0) +    # Flags
        struct.pack("<I", 0) +    # NextCommand
        struct.pack("<Q", message_id) +  # MessageId
        struct.pack("<I", 0) +    # Reserved
        struct.pack("<I", 0) +    # TreeId
        struct.pack("<Q", 0) +    # SessionId
        b"\x00" * 16              # Signature
    )
    dialects = [0x0202]
    body = (
        struct.pack("<H", 36) +          # StructureSize
        struct.pack("<H", len(dialects)) +  # DialectCount
        struct.pack("<H", 1) +           # SecurityMode = SIGNING_ENABLED
        struct.pack("<H", 0) +           # Reserved
        struct.pack("<I", 0) +           # Capabilities
        b"\x00" * 16 +                    # ClientGuid
        struct.pack("<Q", 0)             # ClientStartTime (reserved pre-3.x)
    )
    for d in dialects:
        body += struct.pack("<H", d)

    pdu = smb2_header + body
    netbios_header = struct.pack(">I", len(pdu))  # session type 0x00 + 24-bit length
    return netbios_header + pdu


def _smb2_negotiate_probe(target: str, timeout: float = 4.0) -> dict:
    result: dict[str, Any] = {"port": _SMB_PORT, "reachable": False}
    try:
        with socket.create_connection((target, _SMB_PORT), timeout=timeout) as sock:
            result["reachable"] = True
            sock.settimeout(timeout)
            sock.sendall(_build_smb2_negotiate_request())
            resp = sock.recv(512)
            if len(resp) >= 8:
                nb_len = struct.unpack(">I", resp[:4])[0] & 0x00FFFFFF
                pdu = resp[4:4 + nb_len] if len(resp) >= 4 + nb_len else resp[4:]
                signature = pdu[:4]
                result["response_signature"] = signature.hex()
                if signature == b"\xfeSMB":
                    result["protocol"] = "SMB2/SMB3"
                    # NEGOTIATE_RESPONSE: header(64) + StructureSize(2) + SecurityMode(2) + DialectRevision(2)
                    if len(pdu) >= 64 + 6:
                        dialect = struct.unpack("<H", pdu[64 + 4:64 + 6])[0]
                        result["negotiated_dialect"] = _DIALECT_NAMES.get(dialect, hex(dialect))
                elif signature[:4] == b"\xffSMB":
                    result["protocol"] = "SMB1 (legacy, deprecated)"
                else:
                    result["protocol"] = "unknown/unparsed"
                result["raw_response_hex"] = resp[:96].hex()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)[:120]
    return result


def _smbclient_probe(target: str, timeout: float = 10.0) -> dict | None:
    smbclient = shutil.which("smbclient")
    if not smbclient:
        return None
    try:
        result = run_subprocess([smbclient, "-L", target, "-N"], timeout=timeout)
        return {"returncode": result.returncode, "output": (result.stdout or "")[:2000]}
    except (SandboxError, FileNotFoundError, OSError) as e:
        return {"error": str(e)[:200]}


def run(target: str, timeout: float = 4.0, **kwargs: Any) -> dict:
    """Real SMB2 NEGOTIATE probe on 445/tcp plus optional smbclient -L share listing."""
    host = target.strip()
    if not host:
        return tool_result("network.smb_enum", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    negotiate = _smb2_negotiate_probe(host, timeout=timeout)
    smbclient_result = _smbclient_probe(host)

    if negotiate.get("reachable"):
        if negotiate.get("protocol") == "SMB1 (legacy, deprecated)":
            findings.append(Finding(
                title=f"SMB1 protocol still enabled on {host}:{_SMB_PORT}",
                severity="high",
                confidence="certain",
                affected_asset=f"{host}:{_SMB_PORT}",
                evidence=f"SMB1 signature (\\xffSMB) in negotiate response: {negotiate.get('raw_response_hex', '')}",
                remediation="Disable SMB1 (vulnerable to EternalBlue/WannaCry-class attacks); "
                            "require SMB2.1+ with signing.",
                tool="network.smb_enum",
                references=["CVE-2017-0144", "CWE-327"],
            ))
        elif negotiate.get("protocol") == "SMB2/SMB3":
            findings.append(Finding(
                title=f"SMB service on {host}:{_SMB_PORT} negotiated {negotiate.get('negotiated_dialect', 'unknown dialect')}",
                severity="info",
                confidence="certain",
                affected_asset=f"{host}:{_SMB_PORT}",
                evidence=f"SMB2 NEGOTIATE response signature valid; dialect={negotiate.get('negotiated_dialect')}",
                remediation="Verify SMB signing is required and guest/anonymous access is disabled.",
                tool="network.smb_enum",
            ))
        else:
            findings.append(Finding(
                title=f"Port {_SMB_PORT} open on {host} but SMB negotiate response unrecognised",
                severity="low",
                confidence="medium",
                affected_asset=f"{host}:{_SMB_PORT}",
                evidence=str(negotiate),
                tool="network.smb_enum",
            ))

    if smbclient_result and smbclient_result.get("output", "").strip():
        anon_ok = "NT_STATUS_ACCESS_DENIED" not in smbclient_result["output"]
        findings.append(Finding(
            title=f"smbclient -L against {host} {'succeeded (possible anonymous access)' if anon_ok else 'was denied'}",
            severity="high" if anon_ok else "info",
            confidence="certain",
            affected_asset=host,
            evidence=smbclient_result["output"][:500],
            remediation="Disable anonymous/guest SMB share enumeration (restrict null-session access).",
            tool="network.smb_enum",
            references=["CWE-287"],
        ))

    metadata = {
        "smb2_negotiate_probe": negotiate,
        "smbclient": smbclient_result if smbclient_result is not None else "smbclient not installed on this system — using raw SMB2 negotiate probe only",
    }

    if not findings:
        return tool_result(
            "network.smb_enum", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No SMB service detected on {host}:{_SMB_PORT}",
            metadata=metadata,
        )

    return tool_result(
        "network.smb_enum", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"SMB enumeration found {len(findings)} finding(s) on {host}",
        metadata=metadata,
    )


# Register with tool registry
tool_registry.register("network.smb_enum", run, metadata={
    "name": "network.smb_enum",
    "domain": "network",
    "status": "completed",
    "description": "Real SMB2 NEGOTIATE protocol probe on 445/tcp + optional smbclient -L share enumeration",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "Per-probe timeout in seconds (default: 4.0)",
    },
})
