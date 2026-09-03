"""
NEXUS-STRIKE — Evidence notarization via OpenTimestamps.

What this does
---------------
Cryptographically proves that a piece of evidence (a report, a screenshot,
a packet capture, any file) existed at or before a certain time, by
anchoring a SHA-256 digest of the file into the Bitcoin blockchain via the
OpenTimestamps protocol (https://opentimestamps.org). This is real,
production infrastructure — used by, among others, the Bitcoin Core
project itself to timestamp release signatures. It requires no wallet, no
funds, and no account: a free "calendar" server aggregates many users'
digests into a single Bitcoin transaction (via a Merkle tree), so the cost
of one Bitcoin transaction is shared across everyone who submitted a
digest in that window.

What this does NOT do
----------------------
- It does NOT upload or expose the *contents* of the file — only a SHA-256
  hash of it ever leaves this machine, sent to the calendar server(s).
- It does NOT prove authorship, integrity going forward, or anything about
  *who* created the file — only that *this exact byte sequence* existed
  at or before the timestamp's confirmation time (non-repudiable
  existence-proof, not a signature of identity). Pair this with
  ``nexus.advanced.pq_signing`` if you also need to prove who signed it.
- It does NOT confirm instantly. A freshly created timestamp is anchored
  to a *pending* commitment on a remote calendar; the calendar batches
  pending commitments and writes them into a Bitcoin transaction roughly
  once per hour, and that transaction then needs Bitcoin block
  confirmations on top of it. In practice a stamp typically takes
  somewhere between under an hour and several hours to become verifiable
  on-chain. ``verify()`` on a brand new stamp will correctly report
  ``"pending"`` — that is not a bug, it is what an honest, freshly created
  timestamp looks like. Come back later (or run ``verify()`` again; it
  re-checks the calendar and upgrades the stamp in place if a Bitcoin
  attestation is now available) to see it confirmed.

Implementation notes
---------------------
This module talks to OpenTimestamps calendar servers directly using the
``opentimestamps`` core library (installed as a dependency of the
``opentimestamps-client`` PyPI package: ``pip install
opentimestamps-client``). It deliberately does NOT shell out to the
``ots`` CLI or import ``otsclient.cmds``: in this environment,
``otsclient.cmds`` unconditionally imports ``bitcoin.rpc`` (used only for
its optional "pay from a local Bitcoin wallet" mode, which this module
never uses), and that import chain fails at import time on this machine
because ``python-bitcoinlib``'s ``bitcoin.core.key`` cannot locate a
system OpenSSL shared library via ``ctypes.util.find_library`` on
Windows. The lower-level ``opentimestamps.core.*`` and
``opentimestamps.calendar`` modules — everything actually needed to build,
submit, serialize, and verify a timestamp — import and work fine, so this
module uses those directly. If ``opentimestamps-client`` is not installed
at all, every public method raises ``NotarizationError`` with a clear
install instruction rather than crashing at import time.

Usage
-----
    from nexus.advanced.notarization import EvidenceNotary

    notary = EvidenceNotary()
    ots_path = notary.notarize("report.pdf")     # -> "report.pdf.ots"
    status = notary.verify("report.pdf")          # or notary.verify("report.pdf.ots")
    # status["confirmed"] is False and status["state"] == "pending" for a
    # brand new stamp; re-run verify() later (hours) to see confirmation.
"""
from __future__ import annotations

import binascii
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("nexus.advanced.notarization")

try:
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp, make_merkle_tree
    from opentimestamps.core.notary import (
        BitcoinBlockHeaderAttestation,
        LitecoinBlockHeaderAttestation,
        PendingAttestation,
        UnknownAttestation,
    )
    from opentimestamps.core.serialize import (
        StreamSerializationContext,
        StreamDeserializationContext,
        BadMagicError,
        DeserializationError,
    )
    from opentimestamps.calendar import RemoteCalendar, CommitmentNotFoundError, DEFAULT_AGGREGATORS

    _HAVE_OTS = True
    _OTS_IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover - exercised only if the dep is missing
    _HAVE_OTS = False
    _OTS_IMPORT_ERROR = str(exc)


class NotarizationError(Exception):
    pass


DEFAULT_CALENDAR_URLS = list(DEFAULT_AGGREGATORS) if _HAVE_OTS else [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
]


def _require_ots() -> None:
    if not _HAVE_OTS:
        raise NotarizationError(
            "opentimestamps-client is not installed: pip install opentimestamps-client"
            + (f" (import error: {_OTS_IMPORT_ERROR})" if _OTS_IMPORT_ERROR else "")
        )


@dataclass
class _CalendarResult:
    url: str
    ok: bool
    error: str = ""


class EvidenceNotary:
    """Notarize evidence files by anchoring their SHA-256 digest to the
    Bitcoin blockchain via OpenTimestamps calendar servers.

    See module docstring for exactly what this proves (existence-at-time
    of a specific byte sequence) and does not prove (authorship, identity,
    instant confirmation).
    """

    def __init__(
        self,
        calendar_urls: Optional[list[str]] = None,
        *,
        min_confirmations: int = 1,
        timeout: float = 20.0,
    ) -> None:
        self._calendar_urls = list(calendar_urls or DEFAULT_CALENDAR_URLS)
        self._min_confirmations = max(1, min_confirmations)
        self._timeout = timeout

    # ── notarize ─────────────────────────────────────────────────────
    def notarize(self, file_path: str) -> str:
        """Create a ``.ots`` timestamp receipt for ``file_path`` and write
        it next to the original file (``<file_path>.ots``). Returns the
        path to the receipt.

        Submits the file's SHA-256 digest (nonce-salted, so two identical
        files don't leak a shared digest) to the configured calendar
        servers and records their responses — which, for a brand new
        stamp, are ``PendingAttestation`` entries pointing back at each
        calendar, not yet a Bitcoin confirmation. Raises
        ``NotarizationError`` if the library isn't installed, the file
        doesn't exist, or every calendar server is unreachable.
        """
        _require_ots()
        path = Path(file_path)
        if not path.is_file():
            raise NotarizationError(f"No such file: {file_path}")

        with open(path, "rb") as fd:
            file_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fd)

        # Nonce the commitment (as the `ots` CLI does) so the digest
        # submitted to public calendars can't be correlated back to the
        # plain file digest by an observer who doesn't already have the file.
        nonced_stamp = file_timestamp.timestamp.ops.add(_op_append_nonce())
        merkle_tip = nonced_stamp.ops.add(OpSHA256())

        results = self._submit_to_calendars(merkle_tip)
        successes = [r for r in results if r.ok]
        if not successes:
            details = "; ".join(f"{r.url}: {r.error}" for r in results)
            raise NotarizationError(
                f"Could not reach any OpenTimestamps calendar server: {details}"
            )

        ots_path = str(path) + ".ots"
        with open(ots_path, "xb") as out:
            ctx = StreamSerializationContext(out)
            file_timestamp.serialize(ctx)

        logger.info(
            "Notarized %s -> %s (%d/%d calendars accepted the digest)",
            file_path, ots_path, len(successes), len(results),
        )
        return ots_path

    def _submit_to_calendars(self, merkle_tip: "Timestamp") -> list[_CalendarResult]:
        results: list[_CalendarResult] = []
        for url in self._calendar_urls:
            try:
                calendar = RemoteCalendar(url, user_agent="nexus-strike/EvidenceNotary")
                calendar_timestamp = calendar.submit(merkle_tip.msg, timeout=self._timeout)
                merkle_tip.merge(calendar_timestamp)
                results.append(_CalendarResult(url=url, ok=True))
            except Exception as exc:  # noqa: BLE001 - any network/protocol failure is non-fatal here
                results.append(_CalendarResult(url=url, ok=False, error=str(exc)))
        return results

    # ── verify ───────────────────────────────────────────────────────
    def verify(self, file_path: str) -> dict[str, Any]:
        """Check the notarization status of ``file_path``.

        ``file_path`` may be either the original evidence file (its
        ``.ots`` receipt is assumed to live at ``file_path + ".ots"``) or
        the ``.ots`` receipt file itself.

        Returns a dict:
            state: "confirmed" | "pending" | "unknown"
            confirmed: bool
            digest: hex SHA-256 digest of the original file
            attestations: list of {"type": ..., "detail": ...} entries
                found in the timestamp (pending calendar URIs and/or
                confirmed Bitcoin block heights)
            calendars_checked: list of calendar URLs queried while
                attempting to upgrade a pending stamp

        IMPORTANT: a "pending" result for a timestamp created moments ago
        is expected and correct — OpenTimestamps calendars batch pending
        commitments into a Bitcoin transaction roughly once per hour, and
        that transaction then needs Bitcoin confirmations on top of it.
        There is no instant on-chain verification; call this again later
        to see the stamp upgrade to "confirmed".
        """
        _require_ots()
        ots_path = file_path if file_path.endswith(".ots") else file_path + ".ots"
        if not os.path.isfile(ots_path):
            raise NotarizationError(f"No .ots receipt found at: {ots_path}")

        with open(ots_path, "rb") as fd:
            ctx = StreamDeserializationContext(fd)
            try:
                detached = DetachedTimestampFile.deserialize(ctx)
            except BadMagicError as exc:
                raise NotarizationError(f"{ots_path} is not a valid .ots timestamp file") from exc
            except DeserializationError as exc:
                raise NotarizationError(f"Could not parse {ots_path}: {exc}") from exc

        calendars_checked = self._try_upgrade(detached.timestamp)

        attestations: list[dict[str, Any]] = []
        confirmed = False
        for _msg, attestation in detached.timestamp.all_attestations():
            if isinstance(attestation, BitcoinBlockHeaderAttestation):
                confirmed = True
                attestations.append({"type": "bitcoin", "block_height": attestation.height})
            elif isinstance(attestation, LitecoinBlockHeaderAttestation):
                confirmed = True
                attestations.append({"type": "litecoin", "block_height": attestation.height})
            elif isinstance(attestation, PendingAttestation):
                attestations.append({"type": "pending", "calendar_uri": attestation.uri})
            elif isinstance(attestation, UnknownAttestation):
                attestations.append({"type": "unknown"})

        return {
            "state": "confirmed" if confirmed else ("pending" if attestations else "unknown"),
            "confirmed": confirmed,
            "digest": binascii.hexlify(detached.file_digest).decode("ascii"),
            "attestations": attestations,
            "calendars_checked": calendars_checked,
            "receipt_path": ots_path,
        }

    def _try_upgrade(self, timestamp: "Timestamp") -> list[str]:
        """Ask each pending calendar whether it now has a Bitcoin
        attestation for our commitment; merge in whatever it returns.
        Best-effort — network failures here are not fatal to verify()."""
        checked: list[str] = []
        for sub_msg, attestation in list(timestamp.all_attestations()):
            if not isinstance(attestation, PendingAttestation):
                continue
            checked.append(attestation.uri)
            try:
                calendar = RemoteCalendar(attestation.uri, user_agent="nexus-strike/EvidenceNotary")
                upgraded = calendar.get_timestamp(sub_msg, timeout=self._timeout)
                _merge_into(timestamp, sub_msg, upgraded)
            except CommitmentNotFoundError:
                pass  # not yet confirmed by this calendar
            except Exception as exc:  # noqa: BLE001
                logger.debug("Upgrade check against %s failed: %s", attestation.uri, exc)
        return checked


def _merge_into(root: "Timestamp", target_msg: bytes, upgraded: "Timestamp") -> None:
    """Merge ``upgraded`` (a Timestamp for ``target_msg``) into whichever
    sub-timestamp of ``root`` has that same message."""
    for sub in _walk(root):
        if sub.msg == target_msg:
            sub.merge(upgraded)
            return


def _walk(stamp: "Timestamp"):
    yield stamp
    for sub_stamp in stamp.ops.values():
        yield from _walk(sub_stamp)


def _op_append_nonce():
    from opentimestamps.core.op import OpAppend
    return OpAppend(os.urandom(16))
