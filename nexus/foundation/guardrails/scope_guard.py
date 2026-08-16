"""Target allow-list enforcement for authorised engagements."""
from __future__ import annotations

import ipaddress
import socket
from fnmatch import fnmatchcase
from urllib.parse import urlparse

from nexus.foundation.config import config


class ScopeGuardError(ValueError):
    pass


class ScopeGuard:
    """Reject targets that are not explicitly included in the engagement scope."""

    @staticmethod
    def _hostname(target: str) -> str:
        raw = target.strip()
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            pass
        parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
        hostname = parsed.hostname
        if not hostname:
            raise ScopeGuardError("Target must be a host, IP address, or URL")
        return hostname.rstrip(".").lower()

    @staticmethod
    def _entries() -> list[str]:
        value = str(config.nexus_allowed_targets or "")
        entries = [item.strip().lower().rstrip(".") for item in value.split(",") if item.strip()]
        if not entries:
            raise ScopeGuardError("No allowed targets configured; set NEXUS_ALLOWED_TARGETS")
        return entries

    @classmethod
    def validate(cls, target: str, mode: str = "scan") -> bool:
        if not isinstance(target, str) or not target.strip():
            raise ScopeGuardError("A non-empty target is required")
        hostname = cls._hostname(target)
        entries = cls._entries()

        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None

        for entry in entries:
            if entry == hostname or fnmatchcase(hostname, entry):
                return True
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if address is not None and address in network:
                return True

        if address is None:
            try:
                resolved = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(hostname, None)}
            except OSError as exc:
                raise ScopeGuardError(f"Cannot resolve target {hostname}: {exc}") from exc
            for entry in entries:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    continue
                if resolved and all(item in network for item in resolved):
                    return True

        raise ScopeGuardError(
            f"Target {hostname!r} is outside the configured scope. "
            "Set NEXUS_ALLOWED_TARGETS to an explicit hostname, wildcard, IP, or CIDR."
        )

    @classmethod
    def log(cls, message: str, level: str = "info") -> None:
        return None
