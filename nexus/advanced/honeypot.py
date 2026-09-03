"""
NEXUS-STRIKE — Trivial connection canary (NOT a deception platform).

What this does
---------------
Opens one real TCP listening socket. Every inbound connection is logged
(peer IP:port, local bound port, timestamp) as an audit event via
``AuditGuard.validate(action="honeypot.connection", ...)``, and then the
connection is immediately closed. That's it. This is useful as a cheap,
low-noise tripwire: on a network where nothing should ever legitimately
connect to this port, any connection attempt at all is itself the signal
worth an audit trail entry — a port-scanner, a worm, or a human
noticing an unexpected open port will all trigger it.

What this explicitly does NOT do
----------------------------------
This is NOT a deception platform, and NOT a honeypot in the fuller
industry sense (compare: Cowrie, Dionaea, T-Pot, canarytokens.org's
service emulators). Specifically it does NOT:

  - Emulate any protocol. It never reads or interprets a single byte the
    connecting client sends — no fake SSH banner, no fake HTTP response,
    no fake login prompt. The socket accepts, logs the peer address, and
    closes.
  - Spoof an OS/service fingerprint. A banner-grabbing tool, an nmap
    ``-sV`` scan, or a human running ``nc`` and watching the connection
    close instantly with zero bytes sent will trivially notice this is
    not a real service within one interaction. There is no attempt to
    make this convincing.
  - Capture payloads, log connection contents, rate-limit, or maintain
    any deception state across connections.
  - Defend against anything. It is a detector, not a control.

A determined or even mildly attentive attacker will notice immediately
that this is not a real service. Treat it as a low-cost "did anything
touch this port" tripwire, not a way to occupy or study an attacker.

Usage
-----
    from nexus.advanced.honeypot import CanaryListener

    canary = CanaryListener(host="127.0.0.1", port=0)  # port=0 -> OS picks a free port
    bound_port = canary.start()
    ...
    canary.stop()
"""
from __future__ import annotations

import logging
import socket
import socketserver
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("nexus.advanced.honeypot")


class _CanaryHandler(socketserver.BaseRequestHandler):
    """Accept, log via AuditGuard, close. Reads nothing from the client."""

    def handle(self) -> None:
        peer_host, peer_port = self.client_address[0], self.client_address[1]
        local_port = self.server.server_address[1]
        try:
            from nexus.foundation.guardrails.audit_guard import AuditGuard

            AuditGuard.validate(
                action="honeypot.connection",
                target=f"{peer_host}:{peer_port}",
                local_port=local_port,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        except Exception:  # noqa: BLE001 - audit logging must never crash the listener
            logger.warning("Failed to write audit entry for canary connection from %s:%s",
                            peer_host, peer_port, exc_info=True)
        # Deliberately do not read/write anything else — no protocol emulation.
        try:
            self.request.close()
        except OSError:
            pass


class _CanaryServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class CanaryListener:
    """A trivial TCP connection-canary. See module docstring for exact
    scope: this logs "something connected" via AuditGuard and nothing
    more — no protocol emulation, no fingerprint spoofing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._port = port
        self._server: Optional[_CanaryServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> int:
        """Start listening in a background thread. Returns the actual
        bound port (useful when constructed with ``port=0``, letting the
        OS pick a free ephemeral port — handy for tests)."""
        if self._server is not None:
            raise RuntimeError("CanaryListener is already running; call stop() first")

        self._server = _CanaryServer((self._host, self._port), _CanaryHandler)
        bound_port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True,
            name=f"canary-listener-{bound_port}",
        )
        self._thread.start()
        logger.info("Canary listener started on %s:%d", self._host, bound_port)
        return bound_port

    def stop(self) -> None:
        """Stop the listener and release the port."""
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    @property
    def is_running(self) -> bool:
        return self._server is not None

    @property
    def bound_port(self) -> Optional[int]:
        return self._server.server_address[1] if self._server is not None else None
