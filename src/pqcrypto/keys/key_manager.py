"""
key_manager.py -- high-level key lifecycle management
==========================================================

PURPOSE
---------
Wraps pqcrypto.keys.key_storage with knowledge of the specific algorithms
this project supports (ML-KEM, ML-DSA, X25519, Ed25519), handling: generating
unique key IDs, tracking metadata (algorithm, security level, key type,
creation time, rotation lineage), and rotation/deletion -- so callers work
with `key_id` strings and `KeyRecord`s instead of raw bytes and hand-rolled
bookkeeping.

`KeyRecord` -- returned by every generate_*/list_keys/get_metadata call --
NEVER contains key bytes. Retrieving actual key material is always a
separate, explicit call (`get_public_key` / `get_secret_key`), so secret
material can never leak through what looks like an ordinary metadata listing.

LIMITATION
------------
This is an educational key-management layer, not a substitute for a
production KMS/HSM. See pqcrypto.keys.key_storage for the storage-level
caveats (plaintext-by-default secret storage, filesystem-only access control).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from pqcrypto.kem.classical_kem import ClassicalKEM
from pqcrypto.kem.ml_kem import MLKEM
from pqcrypto.keys.key_storage import KeyStorage, StoredKeyMetadata
from pqcrypto.signatures.classical_signature import ClassicalSignature
from pqcrypto.signatures.ml_dsa import MLDSA

ALGORITHM_ML_KEM = "ML-KEM"
ALGORITHM_ML_DSA = "ML-DSA"
ALGORITHM_X25519 = "X25519"
ALGORITHM_ED25519 = "Ed25519"


class KeyManagerError(ValueError):
    """Raised for unknown key_ids, key_id collisions, or an unsupported algorithm."""


@dataclass(frozen=True)
class KeyRecord:
    """Non-secret information about a managed key. Never contains key bytes."""

    key_id: str
    algorithm: str
    security_level: str
    created_at: str
    rotated_from: str | None = None


def _default_clock() -> str:
    return datetime.now(timezone.utc).isoformat()


class KeyManager:
    """High-level lifecycle management for ML-KEM, ML-DSA, and classical keys.

    Example
    -------
    >>> storage = KeyStorage("/tmp/demo-keys")
    >>> manager = KeyManager(storage)
    >>> record = manager.generate_ml_kem_keypair()
    >>> public_key = manager.get_public_key(record.key_id)
    """

    def __init__(self, storage: KeyStorage, *, clock: Callable[[], str] | None = None) -> None:
        self._storage = storage
        # A caller-injectable clock keeps timestamp generation out of the way
        # of deterministic testing (see tests/test_key_management.py) without
        # making wall-clock behavior implicit anywhere else in this module.
        self._clock = clock or _default_clock

    # ---------------------------------------------------------- generation ---
    def generate_ml_kem_keypair(
        self, security_level: int = 768, *, key_id: str | None = None, passphrase: str | None = None
    ) -> KeyRecord:
        kem = MLKEM(security_level)
        public_key, secret_key = kem.generate_keypair()
        return self._store_new_keypair(
            key_id, ALGORITHM_ML_KEM, str(security_level), public_key, secret_key, passphrase
        )

    def generate_ml_dsa_keypair(
        self, security_level: int = 65, *, key_id: str | None = None, passphrase: str | None = None
    ) -> KeyRecord:
        dsa = MLDSA(security_level)
        public_key, secret_key = dsa.generate_keypair()
        return self._store_new_keypair(
            key_id, ALGORITHM_ML_DSA, str(security_level), public_key, secret_key, passphrase
        )

    def generate_x25519_keypair(
        self, *, key_id: str | None = None, passphrase: str | None = None
    ) -> KeyRecord:
        kem = ClassicalKEM()
        public_key, secret_key = kem.generate_keypair()
        return self._store_new_keypair(
            key_id, ALGORITHM_X25519, "n/a", public_key, secret_key, passphrase
        )

    def generate_ed25519_keypair(
        self, *, key_id: str | None = None, passphrase: str | None = None
    ) -> KeyRecord:
        sig = ClassicalSignature()
        public_key, secret_key = sig.generate_keypair()
        return self._store_new_keypair(
            key_id, ALGORITHM_ED25519, "n/a", public_key, secret_key, passphrase
        )

    # -------------------------------------------------------------- lookup ---
    def get_public_key(self, key_id: str) -> bytes:
        return self._storage.load_public_key(key_id)

    def get_secret_key(self, key_id: str, *, passphrase: str | None = None) -> bytes:
        """Explicitly retrieve secret key material. Deliberately separate from
        get_metadata()/list_keys() so secrets are never exposed incidentally."""
        return self._storage.load_secret_key(key_id, passphrase=passphrase)

    def get_metadata(self, key_id: str) -> KeyRecord:
        stored = self._storage.load_metadata(key_id)
        return self._to_record(stored)

    def list_keys(self) -> list[KeyRecord]:
        return [self._to_record(stored) for stored in self._storage.list_metadata()]

    # ------------------------------------------------------------ lifecycle ---
    def rotate(self, key_id: str, *, passphrase: str | None = None) -> KeyRecord:
        """Generate a fresh keypair of the SAME algorithm/security level as
        `key_id`, linked via `rotated_from`. Does NOT delete the old key --
        callers decide separately when (or whether) to `delete()` it, so a
        rotation can never accidentally destroy the key it's replacing before
        the new one is confirmed usable."""
        old = self.get_metadata(key_id)
        generator = {
            ALGORITHM_ML_KEM: lambda: self.generate_ml_kem_keypair(
                int(old.security_level), passphrase=passphrase
            ),
            ALGORITHM_ML_DSA: lambda: self.generate_ml_dsa_keypair(
                int(old.security_level), passphrase=passphrase
            ),
            ALGORITHM_X25519: lambda: self.generate_x25519_keypair(passphrase=passphrase),
            ALGORITHM_ED25519: lambda: self.generate_ed25519_keypair(passphrase=passphrase),
        }.get(old.algorithm)
        if generator is None:
            raise KeyManagerError(f"cannot rotate unknown algorithm {old.algorithm!r}")
        new_record = generator()
        rotated_record = KeyRecord(
            key_id=new_record.key_id,
            algorithm=new_record.algorithm,
            security_level=new_record.security_level,
            created_at=new_record.created_at,
            rotated_from=key_id,
        )
        self._storage.save_metadata(new_record.key_id, self._to_stored(rotated_record))
        return rotated_record

    def delete(self, key_id: str) -> None:
        self._storage.delete(key_id)

    # -------------------------------------------------------------- helpers ---
    def _store_new_keypair(
        self,
        key_id: str | None,
        algorithm: str,
        security_level: str,
        public_key: bytes,
        secret_key: bytes,
        passphrase: str | None,
    ) -> KeyRecord:
        key_id = key_id or self._new_key_id()
        if self._storage.exists(key_id):
            raise KeyManagerError(f"key_id already in use: {key_id!r}")
        self._storage.save_public_key(key_id, public_key)
        self._storage.save_secret_key(key_id, secret_key, passphrase=passphrase)
        record = KeyRecord(
            key_id=key_id,
            algorithm=algorithm,
            security_level=security_level,
            created_at=self._clock(),
        )
        self._storage.save_metadata(key_id, self._to_stored(record))
        return record

    @staticmethod
    def _to_stored(record: KeyRecord) -> StoredKeyMetadata:
        return StoredKeyMetadata(
            key_id=record.key_id,
            algorithm=record.algorithm,
            security_level=record.security_level,
            key_type="keypair",
            created_at=record.created_at,
            extra={"rotated_from": record.rotated_from} if record.rotated_from else {},
        )

    @staticmethod
    def _to_record(stored: StoredKeyMetadata) -> KeyRecord:
        return KeyRecord(
            key_id=stored.key_id,
            algorithm=stored.algorithm,
            security_level=stored.security_level,
            created_at=stored.created_at,
            rotated_from=stored.extra.get("rotated_from"),
        )

    @staticmethod
    def _new_key_id() -> str:
        return uuid.uuid4().hex
