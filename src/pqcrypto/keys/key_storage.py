"""
key_storage.py -- filesystem persistence for key material
==============================================================

PURPOSE
---------
A clean storage interface that pqcrypto.keys.key_manager builds on, without
key_manager needing to know how or where bytes are actually written.

LIMITATION -- READ THIS BEFORE USING
----------------------------------------
This is an EDUCATIONAL key-storage layer using plain local files. It is NOT
equivalent to an HSM, secure enclave, OS keystore (Windows DPAPI/Credential
Manager, macOS Keychain, Linux keyring), or a production KMS -- there is no
hardware-backed protection, no OS-enforced per-user access control beyond
whatever the filesystem provides, and (unless you explicitly pass a
`passphrase`) private key material is stored in PLAINTEXT on disk, protected
only by filesystem permissions. On Windows in particular, `os.chmod` does not
provide POSIX-style per-user enforcement.

SECRET-AT-REST ENCRYPTION
-----------------------------
Passing a `passphrase` to `save_secret_key`/`load_secret_key` encrypts the
key at rest using scrypt (RFC 7914, a memory-hard password-based KDF -- via
`cryptography`, not reimplemented here) to derive an AES-256 key from the
passphrase, then AES-256-GCM (this project's own pqcrypto.encryption.aes) for
authenticated encryption. The passphrase itself is never hard-coded anywhere
in this project -- it is always supplied by the caller at call time.

PATH SAFETY
-------------
`key_id` is restricted to a small safe character set (letters, digits,
hyphen, underscore) specifically to prevent path traversal -- there is no way
to construct a `key_id` that escapes the storage directory, because
characters like `/`, `\\`, and `.` are rejected outright rather than
sanitized.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pqcrypto.encryption import aes
from pqcrypto.utils import randomness, serialization

_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

# scrypt parameters (RFC 7914's suggested interactive-login-strength values).
# Deliberately not user-configurable here -- a caller weakening these would
# defeat the point of documenting one clear, vetted default.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_SALT_SIZE = 16
_SCRYPT_DERIVED_KEY_SIZE = aes.KEY_SIZE  # 32 bytes, matches AES-256


class KeyStorageError(ValueError):
    """Raised for invalid key IDs, malformed stored data, or storage failures."""


class KeyNotFoundError(KeyStorageError):
    """Raised when a requested key_id has no corresponding stored data."""


@dataclass(frozen=True)
class StoredKeyMetadata:
    """Non-secret metadata about a stored key. Never contains key bytes."""

    key_id: str
    algorithm: str
    security_level: str
    key_type: str  # "public" or "secret" -- which half this metadata describes
    created_at: str  # caller-supplied timestamp (ISO 8601); no wall-clock inside this module
    extra: dict[str, Any]


class KeyStorage:
    """Filesystem persistence for public keys, secret keys, and their metadata.

    Keys are stored under three subdirectories of `base_dir`: `public/`,
    `secret/`, and `metadata/` -- kept physically separate so that, for
    example, backing up or restricting access to only the `public/` directory
    is straightforward and doesn't require inspecting file contents.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self._base_dir = Path(base_dir).resolve()
        self._public_dir = self._base_dir / "public"
        self._secret_dir = self._base_dir / "secret"
        self._metadata_dir = self._base_dir / "metadata"
        for directory in (self._public_dir, self._secret_dir, self._metadata_dir):
            directory.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ public key ---
    def save_public_key(self, key_id: str, data: bytes) -> None:
        """Persist public key bytes in plaintext (public keys need no confidentiality)."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes, got {type(data).__name__}")
        path = self._resolve(self._public_dir, key_id)
        path.write_bytes(bytes(data))

    def load_public_key(self, key_id: str) -> bytes:
        path = self._resolve(self._public_dir, key_id)
        if not path.exists():
            raise KeyNotFoundError(f"no public key stored for key_id={key_id!r}")
        return path.read_bytes()

    # ------------------------------------------------------------ secret key ---
    def save_secret_key(self, key_id: str, data: bytes, *, passphrase: str | None = None) -> None:
        """Persist secret key bytes.

        Without `passphrase`: stored in PLAINTEXT (see module docstring).
        With `passphrase`: encrypted at rest (scrypt + AES-256-GCM).
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes, got {type(data).__name__}")
        path = self._resolve(self._secret_dir, key_id)
        payload = bytes(data) if passphrase is None else self._encrypt_with_passphrase(data, passphrase)
        path.write_bytes(payload)
        self._restrict_permissions(path)

    def load_secret_key(self, key_id: str, *, passphrase: str | None = None) -> bytes:
        """Load secret key bytes. Pass the SAME `passphrase` used at save time
        if the key was encrypted at rest."""
        path = self._resolve(self._secret_dir, key_id)
        if not path.exists():
            raise KeyNotFoundError(f"no secret key stored for key_id={key_id!r}")
        payload = path.read_bytes()
        if passphrase is None:
            return payload
        return self._decrypt_with_passphrase(payload, passphrase)

    # -------------------------------------------------------------- metadata ---
    def save_metadata(self, key_id: str, metadata: StoredKeyMetadata) -> None:
        if not isinstance(metadata, StoredKeyMetadata):
            raise TypeError(f"metadata must be StoredKeyMetadata, got {type(metadata).__name__}")
        path = self._resolve(self._metadata_dir, key_id)
        payload = serialization.dumps(
            {
                "key_id": metadata.key_id,
                "algorithm": metadata.algorithm,
                "security_level": metadata.security_level,
                "key_type": metadata.key_type,
                "created_at": metadata.created_at,
                "extra": metadata.extra,
            }
        )
        path.write_bytes(payload)

    def load_metadata(self, key_id: str) -> StoredKeyMetadata:
        path = self._resolve(self._metadata_dir, key_id)
        if not path.exists():
            raise KeyNotFoundError(f"no metadata stored for key_id={key_id!r}")
        return self._parse_metadata(key_id, path.read_bytes())

    def list_metadata(self) -> list[StoredKeyMetadata]:
        """Return metadata for every stored key. Raises on the first
        corrupted metadata file encountered, naming which key_id -- silently
        skipping malformed entries would hide data loss rather than surface it."""
        results = []
        for path in sorted(self._metadata_dir.glob("*.json")):
            key_id = path.stem
            results.append(self._parse_metadata(key_id, path.read_bytes()))
        return results

    # ---------------------------------------------------------------- misc ---
    def exists(self, key_id: str) -> bool:
        """True if EITHER a public key, a secret key, or metadata is stored
        for `key_id`."""
        return (
            self._resolve(self._public_dir, key_id).exists()
            or self._resolve(self._secret_dir, key_id).exists()
            or self._resolve(self._metadata_dir, key_id).exists()
        )

    def delete(self, key_id: str) -> None:
        """Remove all stored data (public key, secret key, metadata) for
        `key_id`. Missing components are silently skipped -- deleting an
        already-partially-deleted key_id is not an error."""
        for directory in (self._public_dir, self._secret_dir, self._metadata_dir):
            path = self._resolve(directory, key_id)
            if path.exists():
                path.unlink()

    # -------------------------------------------------------------- helpers ---
    def _resolve(self, directory: Path, key_id: str) -> Path:
        if not isinstance(key_id, str) or not _KEY_ID_PATTERN.match(key_id):
            raise KeyStorageError(
                f"invalid key_id: {key_id!r} (must match {_KEY_ID_PATTERN.pattern})"
            )
        suffix = ".json" if directory is self._metadata_dir else ".bin"
        return directory / f"{key_id}{suffix}"

    def _parse_metadata(self, key_id: str, raw: bytes) -> StoredKeyMetadata:
        try:
            obj = serialization.loads(
                raw,
                required_fields=(
                    "key_id",
                    "algorithm",
                    "security_level",
                    "key_type",
                    "created_at",
                    "extra",
                ),
            )
        except serialization.SerializationError as exc:
            raise KeyStorageError(f"corrupted metadata for key_id={key_id!r}: {exc}") from exc
        return StoredKeyMetadata(
            key_id=obj["key_id"],
            algorithm=obj["algorithm"],
            security_level=obj["security_level"],
            key_type=obj["key_type"],
            created_at=obj["created_at"],
            extra=obj["extra"],
        )

    @staticmethod
    def _restrict_permissions(path: Path) -> None:
        """Best-effort owner-only file permissions. No-op-ish on Windows --
        see module docstring's limitation notice."""
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    @staticmethod
    def _encrypt_with_passphrase(data: bytes, passphrase: str) -> bytes:
        if not isinstance(passphrase, str) or not passphrase:
            raise TypeError("passphrase must be a non-empty str")
        salt = randomness.random_bytes(_SCRYPT_SALT_SIZE)
        key = KeyStorage._derive_passphrase_key(passphrase, salt)
        package = aes.encrypt(bytes(data), key)
        return salt + package.nonce + package.ciphertext

    @staticmethod
    def _decrypt_with_passphrase(payload: bytes, passphrase: str) -> bytes:
        if not isinstance(passphrase, str) or not passphrase:
            raise TypeError("passphrase must be a non-empty str")
        header_size = _SCRYPT_SALT_SIZE + aes.NONCE_SIZE
        if len(payload) < header_size:
            raise KeyStorageError("stored key data is malformed (too short)")
        salt = payload[:_SCRYPT_SALT_SIZE]
        nonce = payload[_SCRYPT_SALT_SIZE:header_size]
        ciphertext = payload[header_size:]
        key = KeyStorage._derive_passphrase_key(passphrase, salt)
        try:
            return aes.decrypt(aes.AESGCMCiphertext(nonce, ciphertext), key)
        except aes.AuthenticationError as exc:
            raise KeyStorageError(
                "failed to decrypt stored key: wrong passphrase or corrupted data"
            ) from exc

    @staticmethod
    def _derive_passphrase_key(passphrase: str, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=_SCRYPT_DERIVED_KEY_SIZE,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        )
        return kdf.derive(passphrase.encode("utf-8"))
