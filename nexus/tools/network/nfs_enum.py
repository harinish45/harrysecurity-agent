#!/usr/bin/env python3
"""
NEXUS-STRIKE — network.nfs_enum
Domain: network

Previously a plain generic port sweep (byte-for-byte identical to
snmp_enum.py, smb_enum.py, etc. before this fix) — it never spoke NFS or
even the ONC RPC portmapper protocol. Caught during this session's audit.

Now: a real ONC RPC (Sun RPC, RFC 5531) NULL-procedure call to the
portmapper (port 111/tcp) — the same handshake `rpcinfo -p` performs — to
confirm a genuine RPC service is listening, plus a real check for the NFS
server port (2049/tcp). If `showmount` is available on PATH, it is used
for a real (unauthenticated, read-only) NFS export listing, which is the
standard way to enumerate NFS exports.
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

_PORTMAPPER_PORT = 111
_NFSD_PORT = 2049
_PORTMAPPER_PROG = 100000
_PORTMAPPER_VERS = 2
_PROC_NULL = 0


def _build_rpc_null_call(xid: int = 0x4E455853) -> bytes:  # 0x4E455853 = "NEXS"
    """Build a real ONC RPC (RFC 5531) CALL message body for the portmapper's
    NULL procedure — the minimal, side-effect-free RPC exchange used to
    confirm an RPC service is genuinely listening and speaking the protocol
    (this is exactly what `rpcinfo -p` does under the hood)."""
    body = struct.pack(
        ">IIIIII",
        xid,             # transaction id
        0,                # msg_type = CALL
        2,                # rpcvers = 2
        _PORTMAPPER_PROG,  # prog = portmapper
        _PORTMAPPER_VERS,  # vers
        _PROC_NULL,       # proc = NULL
    )
    body += struct.pack(">II", 0, 0)  # cred: flavor=AUTH_NULL, length=0
    body += struct.pack(">II", 0, 0)  # verf: flavor=AUTH_NULL, length=0
    # TCP record-marking header: high bit set = last fragment, low 31 bits = length
    record_header = struct.pack(">I", 0x80000000 | len(body))
    return record_header + body


def _rpc_null_probe(target: str, timeout: float = 4.0) -> dict:
    """Real RPC NULL call against the portmapper on port 111/tcp."""
    result: dict[str, Any] = {"port": _PORTMAPPER_PORT, "reachable": False}
    try:
        with socket.create_connection((target, _PORTMAPPER_PORT), timeout=timeout) as sock:
            result["reachable"] = True
            sock.settimeout(timeout)
            sock.sendall(_build_rpc_null_call())
            resp = sock.recv(256)
            if len(resp) >= 4:
                (frag_hdr,) = struct.unpack(">I", resp[:4])
                frag_len = frag_hdr & 0x7FFFFFFF
                body = resp[4:4 + frag_len] if len(resp) >= 4 + frag_len else resp[4:]
                if len(body) >= 12:
                    xid, msg_type, reply_stat = struct.unpack(">III", body[:12])
                    result["rpc_reply_valid"] = (msg_type == 1)  # 1 = REPLY
                    result["rpc_accepted"] = (reply_stat == 0)   # 0 = MSG_ACCEPTED
                    result["raw_reply_hex"] = resp[:64].hex()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)[:120]
    return result


def _nfsd_port_probe(target: str, timeout: float = 3.0) -> dict:
    try:
        with socket.create_connection((target, _NFSD_PORT), timeout=timeout):
            return {"port": _NFSD_PORT, "reachable": True}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"port": _NFSD_PORT, "reachable": False, "error": str(e)[:120]}


def _showmount_probe(target: str, timeout: float = 10.0) -> dict | None:
    showmount = shutil.which("showmount")
    if not showmount:
        return None
    try:
        result = run_subprocess([showmount, "-e", target], timeout=timeout)
        return {"returncode": result.returncode, "output": (result.stdout or "")[:2000]}
    except (SandboxError, FileNotFoundError, OSError) as e:
        return {"error": str(e)[:200]}


def run(target: str, timeout: float = 4.0, **kwargs: Any) -> dict:
    """Real NFS/ONC-RPC enumeration: portmapper NULL call, NFS port probe,
    and (when available) `showmount -e` export listing."""
    host = target.strip()
    if not host:
        return tool_result("network.nfs_enum", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []

    rpc_result = _rpc_null_probe(host, timeout=timeout)
    nfsd_result = _nfsd_port_probe(host, timeout=timeout)
    showmount_result = _showmount_probe(host)

    if rpc_result.get("reachable"):
        if rpc_result.get("rpc_reply_valid") and rpc_result.get("rpc_accepted"):
            findings.append(Finding(
                title=f"ONC RPC portmapper responding on {host}:{_PORTMAPPER_PORT}",
                severity="medium",
                confidence="certain",
                affected_asset=f"{host}:{_PORTMAPPER_PORT}",
                evidence=f"RPC NULL call accepted; reply header: {rpc_result.get('raw_reply_hex', '')}",
                remediation="Restrict RPC portmapper/rpcbind access to trusted networks; NFS "
                            "exports should never be reachable from untrusted networks.",
                tool="network.nfs_enum",
                references=["RFC-5531", "CWE-306"],
            ))
        else:
            findings.append(Finding(
                title=f"Port {_PORTMAPPER_PORT} open on {host} but did not return a valid RPC reply",
                severity="low",
                confidence="medium",
                affected_asset=f"{host}:{_PORTMAPPER_PORT}",
                evidence=str(rpc_result),
                remediation="Verify the service on this port; a non-RPC service may be listening.",
                tool="network.nfs_enum",
            ))

    if nfsd_result.get("reachable"):
        findings.append(Finding(
            title=f"NFS server port open on {host}:{_NFSD_PORT}",
            severity="medium",
            confidence="certain",
            affected_asset=f"{host}:{_NFSD_PORT}",
            evidence="TCP connection established to the standard NFS server port (2049).",
            remediation="Ensure NFS exports use host allow-lists and are not reachable from "
                        "untrusted networks; prefer NFSv4 with Kerberos.",
            tool="network.nfs_enum",
            references=["CWE-306"],
        ))

    if showmount_result and showmount_result.get("output", "").strip():
        findings.append(Finding(
            title=f"NFS exports enumerated via showmount on {host}",
            severity="high" if "Export list" in showmount_result["output"] else "info",
            confidence="certain",
            affected_asset=host,
            evidence=showmount_result["output"][:500],
            remediation="Review exported filesystems; restrict export ACLs to authorised hosts only.",
            tool="network.nfs_enum",
            references=["CWE-306"],
        ))

    metadata = {
        "portmapper_probe": rpc_result,
        "nfsd_port_probe": nfsd_result,
        "showmount": showmount_result if showmount_result is not None else "showmount not installed on this system — using raw RPC/port probes only",
    }

    if not findings:
        return tool_result(
            "network.nfs_enum", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No NFS/RPC services detected on {host} (portmapper 111 and NFS 2049 both unreachable)",
            metadata=metadata,
        )

    return tool_result(
        "network.nfs_enum", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"NFS/RPC enumeration found {len(findings)} finding(s) on {host}",
        metadata=metadata,
    )


# Register with tool registry
tool_registry.register("network.nfs_enum", run, metadata={
    "name": "network.nfs_enum",
    "domain": "network",
    "status": "completed",
    "description": "Real ONC RPC portmapper NULL call + NFS port probe + showmount export enumeration",
    "parameters": {
        "target": "Target IP or hostname",
        "timeout": "Per-probe timeout in seconds (default: 4.0)",
    },
})
