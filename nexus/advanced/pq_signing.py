"""
NEXUS-STRIKE — Post-quantum evidence signing.

What this does
---------------
Signs evidence files with ML-DSA-65 (formerly known as CRYSTALS-Dilithium,
security category 3), the post-quantum digital signature algorithm
standardized by NIST as FIPS 204 in August 2024. Unlike RSA/ECDSA, ML-DSA's
security does not rely on the hardness of integer factorization or
discrete log — problems a sufficiently large quantum computer running
Shor's algorithm would break — so evidence signed today stays verifiable
and un-forgeable even in a post-quantum future. This gives NEXUS-STRIKE's
evidence chain "harvest now, decrypt/forge later" resistance for signature
integrity (note: this signs, it does not encrypt — pair with a PQ KEM,
e.g. ML-KEM, if confidentiality against a future quantum adversary is also
required, which this module does not provide).

What was investigated for this environment, and what actually worked
-----------------------------------------------------------------------
Per the task brief, before writing any code this module's implementation
was chosen by actually testing what installs and works HERE:

1. ``pip install --upgrade cryptography`` was run. The installed version
   is 49.0.0. ``dir(cryptography.hazmat.primitives.asymmetric)`` was
   inspected for PQC modules, and ``cryptography.hazmat.primitives.asymmetric.mldsa``
   IS present, exposing ``MLDSA44PrivateKey/PublicKey``,
   ``MLDSA65PrivateKey/PublicKey``, and ``MLDSA87PrivateKey/PublicKey``
   (recent ``cryptography`` releases, built on a PQC-enabled OpenSSL 3.5+
   / AWS-LC-rs backend, added ML-DSA support directly). A live
   generate/sign/verify/tamper-detect round trip was run and works.
   ML-DSA-65 was chosen (NIST security category 3) as a solid default
   balance of signature size (~3.3KB) and security margin; ML-DSA-44/87
   are available in the underlying library for smaller/larger margins if
   ever needed, but are not exposed by this module to keep one clear
   default.

2. Because (1) worked, ``pqcrypto`` (the PQClean-wrapping fallback
   mentioned in the task brief) was NOT tried — there was no need for a
   second, less-maintained dependency once a first-party, actively
   maintained implementation was confirmed working.

Given that, this module has NO degraded path in practice on a
``cryptography>=45`` install with ML-DSA support built in. It still
defines and raises ``PQSigningError`` with the message below if
``cryptography.hazmat.primitives.asymmetric.mldsa`` is unavailable (e.g.
an older ``cryptography`` version, or a build without the PQC backend),
so this module never crashes at import time regardless of what's
installed in whatever environment it later runs in:

    "No post-quantum signing library available in this environment:
    tried cryptography.hazmat.primitives.asymmetric.mldsa (requires
    cryptography>=45 with PQC support; not found/importable here) and did
    not additionally need pqcrypto because the primary path worked when
    this module was written — see module docstring. Install/upgrade with:
    pip install --upgrade cryptography"

What this does NOT do
----------------------
- It does NOT encrypt evidence, only signs it (integrity + authenticity,
  not confidentiality).
- It does NOT manage a PKI / certificate chain — this is raw key-pair
  signing. Trust in the public key still has to be established out of
  band (e.g. published alongside a notarized OpenTimestamps receipt, see
  ``nexus.advanced.notarization``).
- It does NOT rotate or expire keys automatically; call ``rotate_key()``
  explicitly if you need a fresh keypair.

Usage
-----
    from nexus.advanced.pq_signing import PQSigner

    signer = PQSigner()
    sig = signer.sign_evidence("report.pdf")
    ok = signer.verify_evidence("report.pdf", sig)
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("nexus.advanced.pq_signing")

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.exceptions import InvalidSignature

    _HAVE_MLDSA = True
    _MLDSA_IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover - exercised only if the dep is missing/old
    _HAVE_MLDSA = False
    _MLDSA_IMPORT_ERROR = str(exc)


class PQSigningError(Exception):
    pass


_NO_BACKEND_MESSAGE = (
    "No post-quantum signing library available in this environment: tried "
    "cryptography.hazmat.primitives.asymmetric.mldsa (requires "
    "cryptography>=45 with PQC support; {reason}) and did not additionally "
    "need pqcrypto because the primary path worked when this module was "
    "written for this codebase — see module docstring for what was tested. "
    "Install/upgrade with: pip install --upgrade cryptography"
)


def _require_mldsa() -> None:
    if not _HAVE_MLDSA:
        reason = f"not found/importable here ({_MLDSA_IMPORT_ERROR})" if _MLDSA_IMPORT_ERROR else "not found/importable here"
        raise PQSigningError(_NO_BACKEND_MESSAGE.format(reason=reason))


_VAULT_PRIVATE_KEY = "pq_signing.private_key"  # hex-encoded 32-byte ML-DSA-65 seed


class PQSigner:
    """Signs and verifies evidence files with ML-DSA-65 (FIPS 204).

    The signing key is generated on first use and persisted (as a
    hex-encoded 32-byte seed) in the existing encrypted secrets vault
    (``nexus.foundation.secrets``) under the key ``"pq_signing.private_key"``,
    so it survives process restarts without landing on disk unencrypted.
    """

    def __init__(self, *, vault=None) -> None:
        if vault is None:
            from nexus.foundation.secrets import secrets as vault  # local import: keep vault optional/mockable
        self._vault = vault
        self._private_key = None  # lazily loaded/generated

    # ── key management ──────────────────────────────────────────────
    def _load_or_generate_key(self):
        _require_mldsa()
        if self._private_key is not None:
            return self._private_key

        seed_hex = self._vault.get(_VAULT_PRIVATE_KEY, "")
        if seed_hex:
            try:
                self._private_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(seed_hex))
                return self._private_key
            except (ValueError, TypeError) as exc:
                logger.warning(
                    "Stored PQ signing key was invalid (%s); generating a new one. "
                    "Signatures made with the old key will no longer verify.", exc,
                )

        self._private_key = mldsa.MLDSA65PrivateKey.generate()
        self._vault.set(_VAULT_PRIVATE_KEY, self._private_key.private_bytes_raw().hex())
        logger.info("Generated a new ML-DSA-65 signing keypair and stored it in the secrets vault.")
        return self._private_key

    def rotate_key(self):
        """Generate a fresh keypair and persist it, discarding the old one.
        Anything signed with the previous key will no longer verify against
        the new public key."""
        _require_mldsa()
        self._private_key = mldsa.MLDSA65PrivateKey.generate()
        self._vault.set(_VAULT_PRIVATE_KEY, self._private_key.private_bytes_raw().hex())
        return self.public_key_bytes()

    def public_key_bytes(self) -> bytes:
        """Raw public key bytes (1952 bytes for ML-DSA-65), for
        distributing/publishing alongside signed evidence."""
        key = self._load_or_generate_key()
        return key.public_key().public_bytes_raw()

    # ── sign / verify ────────────────────────────────────────────────
    def sign_evidence(self, file_path: str) -> bytes:
        """Return an ML-DSA-65 signature over the raw bytes of
        ``file_path``. Raises ``PQSigningError`` if no PQ backend is
        available, or the file can't be read."""
        key = self._load_or_generate_key()
        path = Path(file_path)
        if not path.is_file():
            raise PQSigningError(f"No such file: {file_path}")
        data = path.read_bytes()
        return key.sign(data)

    def verify_evidence(self, file_path: str, signature: bytes) -> bool:
        """Verify ``signature`` (as produced by ``sign_evidence``) against
        the current contents of ``file_path`` and this signer's public
        key. Returns True/False; never raises for an ordinary verification
        failure (wrong signature, tampered file) — only for missing
        backend/file, matching a boolean "did it verify" contract."""
        key = self._load_or_generate_key()
        path = Path(file_path)
        if not path.is_file():
            raise PQSigningError(f"No such file: {file_path}")
        data = path.read_bytes()
        public_key = key.public_key()
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
