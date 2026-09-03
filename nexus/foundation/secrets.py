"""Encrypted secrets vault.

Replaces the historical no-op stub (``SecretsManager.get()`` used to always
return the caller's ``default`` with no real storage behind it). Secrets are
encrypted at rest with Fernet (AES-128-CBC + HMAC, from the ``cryptography``
package) under a master key that is either supplied via ``NEXUS_MASTER_KEY``
or generated once and stored locally with restrictive permissions.

Design goals:
- Never raise out of ``get()``. A vault that isn't configured yet, or whose
  key doesn't decrypt the store, must degrade to returning ``default`` (with
  a logged warning) rather than crashing every caller that asks for a secret.
- ``set()``/``delete()``/``rotate_key()`` are allowed to raise — those are
  explicit administrative actions, not opportunistic reads.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

logger = logging.getLogger("nexus.secrets")

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised only if the dep is missing
    _HAVE_CRYPTO = False


class SecretsError(Exception):
    pass


def _vault_dir() -> Path:
    override = os.environ.get("NEXUS_VAULT_DIR")
    path = Path(override) if override else Path.home() / ".nexus"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _restrict(path: Path) -> None:
    """Best-effort 0600 permissions. Silently ignored on filesystems that
    don't support POSIX mode bits (e.g. some Windows configurations)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


class SecretsManager:
    """Encrypted key/value vault for API keys, credentials, and tokens."""

    _KEY_FILE = "secret.key"
    _STORE_FILE = "secrets.enc"

    def __init__(self, vault_dir: Path | None = None) -> None:
        self._dir = vault_dir or _vault_dir()
        self._fernet: "Fernet | None" = None

    # ── key management ──────────────────────────────────────────────
    def _derive_key_from_env(self, material: str) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"nexus-strike-vault", info=b"secrets")
        return base64.urlsafe_b64encode(hkdf.derive(material.encode("utf-8")))

    def _load_or_create_key(self) -> bytes:
        env_material = os.environ.get("NEXUS_MASTER_KEY")
        if env_material:
            return self._derive_key_from_env(env_material)

        key_path = self._dir / self._KEY_FILE
        if key_path.exists():
            return key_path.read_bytes().strip()

        key = Fernet.generate_key()
        key_path.write_bytes(key)
        _restrict(key_path)
        logger.warning(
            "No NEXUS_MASTER_KEY set — generated a local vault key at %s. "
            "Set NEXUS_MASTER_KEY explicitly in production so the vault survives "
            "host loss/rotation and isn't tied to one machine's filesystem.",
            key_path,
        )
        return key

    def _client(self) -> "Fernet":
        if not _HAVE_CRYPTO:
            raise SecretsError(
                "The 'cryptography' package is required for the secrets vault. "
                "Install it with: pip install cryptography"
            )
        if self._fernet is None:
            self._fernet = Fernet(self._load_or_create_key())
        return self._fernet

    # ── store I/O ────────────────────────────────────────────────────
    def _store_path(self) -> Path:
        return self._dir / self._STORE_FILE

    def _read_store(self) -> dict[str, Any]:
        path = self._store_path()
        if not path.exists():
            return {}
        blob = path.read_bytes()
        if not blob:
            return {}
        decrypted = self._client().decrypt(blob)
        return json.loads(decrypted.decode("utf-8"))

    def _write_store(self, data: dict[str, Any]) -> None:
        path = self._store_path()
        encrypted = self._client().encrypt(json.dumps(data, sort_keys=True).encode("utf-8"))
        path.write_bytes(encrypted)
        _restrict(path)

    # ── public API ───────────────────────────────────────────────────
    def get(self, key: str, default: str = "") -> str:
        """Return the decrypted secret for ``key``, or ``default``.

        Never raises: any failure (crypto unavailable, corrupt store, wrong
        key, missing entry) is logged and treated as "not configured."
        """
        try:
            store = self._read_store()
        except SecretsError as exc:
            logger.warning("Secrets vault unavailable, using default for %r: %s", key, exc)
            return default
        except (InvalidToken, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Secrets vault could not be decrypted, using default for %r: %s", key, exc)
            return default
        except OSError as exc:
            logger.warning("Secrets vault read failed, using default for %r: %s", key, exc)
            return default
        return store.get(key, default)

    def set(self, key: str, value: str) -> None:
        store = self._read_store()
        store[key] = value
        self._write_store(store)

    def delete(self, key: str) -> None:
        store = self._read_store()
        if key in store:
            del store[key]
            self._write_store(store)

    def list_keys(self) -> list[str]:
        return sorted(self._read_store().keys())

    def rotate_key(self, new_master_key: str | None = None) -> None:
        """Re-encrypt the store under a freshly generated (or supplied) key."""
        store = self._read_store()
        key_path = self._dir / self._KEY_FILE
        if new_master_key:
            self._fernet = Fernet(self._derive_key_from_env(new_master_key))
        else:
            new_key = Fernet.generate_key()
            key_path.write_bytes(new_key)
            _restrict(key_path)
            self._fernet = Fernet(new_key)
        self._write_store(store)
        logger.info("Vault key rotated (%d secrets re-encrypted).", len(store))


secrets = SecretsManager()
