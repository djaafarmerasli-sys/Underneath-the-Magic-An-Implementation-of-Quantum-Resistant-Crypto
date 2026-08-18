"""
file_encryptor.py -- high-level hybrid file encryption
==========================================================

GOAL
------
Tie every lower layer together into one operation an application actually
wants to call:

    input bytes
        |
        v
    hybrid key establishment (pqcrypto.hybrid.key_exchange)
        |
        v
    KDF (pqcrypto.hybrid.kdf, via key_exchange's session key)
        |
        v
    AES-256-GCM (pqcrypto.encryption.aes)
        |
        v
    EncryptedFilePackage  -- self-describing, ready to serialize/transmit

ML-KEM is never used to touch the file's bytes directly -- see aes.py's
module docstring for why. This module only ever hands the *derived* AES-256
session key to AES-GCM; the KEM/KDF layers below it are opaque here.

WHAT'S IN THE PACKAGE, AND WHY
-----------------------------------
`EncryptedFilePackage` intentionally carries enough NON-SECRET metadata to
let a recipient reproduce every step of decryption without guessing:
format version, the hybrid KEM ciphertext (classical + ML-KEM components,
each tagged with its own algorithm identifier), the AEAD's nonce, and the
authenticated ciphertext bytes. None of that is secret -- an eavesdropper
who captures the whole package still cannot recover the plaintext or the
session key without the recipient's private key material. The package NEVER
contains: private keys, the derived AES key, or plaintext.

Binding the metadata to the ciphertext: the package's algorithm/version
fields are passed to AES-GCM as *associated data* (see aes.py), so an
attacker cannot silently swap the declared algorithm identifiers, KEM
ciphertext, or version onto a captured ciphertext -- any such tampering
fails authentication in file_decryptor.py exactly like tampering the
ciphertext bytes themselves.

STREAMING LIMITATION
------------------------
This module loads the entire plaintext into memory and encrypts it as a
SINGLE AES-GCM operation. This is intentional and safe for the file sizes
this educational project targets, but it is NOT a chunked/streaming AEAD
construction: do not use it as-is for files too large to comfortably hold in
memory twice over (plaintext + ciphertext). A production streaming design
would split the file into authenticated chunks with per-chunk nonces and
sequence binding -- out of scope here; see docs/architecture.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcrypto.encryption import aes
from pqcrypto.hybrid.kdf import derive_key
from pqcrypto.hybrid.key_exchange import (
    HybridKeyExchange,
    HybridKeyExchangeError,
    HybridPublicKey,
)
from pqcrypto.utils import serialization

FORMAT_VERSION = 1

# Fixed KDF domain-separation label for "the AES key used to encrypt THIS
# file", distinct from the label key_exchange.py uses for its own hybrid
# session key (see pqcrypto.hybrid.kdf's module docstring on domain
# separation). Bumping this would be a breaking format change.
FILE_ENCRYPTION_KDF_CONTEXT = b"pqcrypto-file-encryption-v1"


class FileEncryptorError(ValueError):
    """Raised for invalid arguments to encrypt_file(), or a hybrid
    key-establishment failure encountered while encrypting."""


@dataclass(frozen=True)
class EncryptedFilePackage:
    """Everything a recipient needs, alongside their HybridSecretKey, to
    authenticate and decrypt this package. Contains no secret material.

    `associated_data()` reproduces the exact bytes bound into the AES-GCM
    authentication tag -- file_decryptor.py MUST use the identical method to
    verify a package it did not create, or authentication will (correctly)
    fail even for an untampered package.
    """

    version: int
    kdf_algorithm: str
    aead_algorithm: str
    classical_algorithm: str
    ml_kem_security_level: int
    classical_ciphertext: bytes
    pq_ciphertext: bytes
    nonce: bytes
    ciphertext: bytes

    def associated_data(self) -> bytes:
        """Canonical, deterministic encoding of every non-secret field EXCEPT
        the AEAD nonce/ciphertext themselves (those are AES-GCM's own inputs,
        not part of the AAD) -- binding version and algorithm identifiers to
        the ciphertext so none of them can be swapped undetected."""
        return serialization.dumps(
            {
                "version": self.version,
                "kdf_algorithm": self.kdf_algorithm,
                "aead_algorithm": self.aead_algorithm,
                "classical_algorithm": self.classical_algorithm,
                "ml_kem_security_level": self.ml_kem_security_level,
            }
        )

    def to_bytes(self) -> bytes:
        """Serialize the full package (still containing no secrets) to bytes
        suitable for writing to a file or transmitting."""
        return serialization.dumps(
            {
                "version": self.version,
                "kdf_algorithm": self.kdf_algorithm,
                "aead_algorithm": self.aead_algorithm,
                "classical_algorithm": self.classical_algorithm,
                "ml_kem_security_level": self.ml_kem_security_level,
                "classical_ciphertext": serialization.encode_bytes(self.classical_ciphertext),
                "pq_ciphertext": serialization.encode_bytes(self.pq_ciphertext),
                "nonce": serialization.encode_bytes(self.nonce),
                "ciphertext": serialization.encode_bytes(self.ciphertext),
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedFilePackage":
        """Inverse of to_bytes(). Only validates STRUCTURE (required fields,
        valid base64/JSON) -- it deliberately does NOT validate that the
        version/algorithms are ones this project's current code supports.
        That check belongs to the decryptor, which knows what it can
        actually process; a generic parser rejecting unfamiliar-but
        well-formed versions would block future algorithm upgrades this
        format is explicitly designed to allow (see module docstring)."""
        obj = serialization.loads(
            data,
            required_fields=(
                "version",
                "kdf_algorithm",
                "aead_algorithm",
                "classical_algorithm",
                "ml_kem_security_level",
                "classical_ciphertext",
                "pq_ciphertext",
                "nonce",
                "ciphertext",
            ),
        )
        try:
            return cls(
                version=int(obj["version"]),
                kdf_algorithm=str(obj["kdf_algorithm"]),
                aead_algorithm=str(obj["aead_algorithm"]),
                classical_algorithm=str(obj["classical_algorithm"]),
                ml_kem_security_level=int(obj["ml_kem_security_level"]),
                classical_ciphertext=serialization.decode_bytes(obj["classical_ciphertext"]),
                pq_ciphertext=serialization.decode_bytes(obj["pq_ciphertext"]),
                nonce=serialization.decode_bytes(obj["nonce"]),
                ciphertext=serialization.decode_bytes(obj["ciphertext"]),
            )
        except (TypeError, ValueError) as exc:
            raise FileEncryptorError(f"malformed encrypted file package: {exc}") from exc


def encrypt_file(
    plaintext: bytes,
    recipient_public_key: HybridPublicKey,
    *,
    ml_kem_security_level: int = 768,
) -> EncryptedFilePackage:
    """Encrypt `plaintext` for the holder of `recipient_public_key`.

    Performs, in order: a fresh hybrid (X25519 + ML-KEM) key establishment
    against the recipient's public key, HKDF derivation of a file-specific
    AES-256 key from the resulting session key (via a domain-separation
    context distinct from the raw hybrid session key -- see module
    docstring), then AES-256-GCM encryption of `plaintext` with the
    package's own metadata bound in as associated data.

    Parameters
    ----------
    plaintext : the file contents to encrypt, as bytes.
    recipient_public_key : the recipient's HybridPublicKey (see
        pqcrypto.hybrid.key_exchange). A fresh hybrid handshake is performed
        against it for every call -- this function never reuses key
        material across calls.
    ml_kem_security_level : the ML-KEM parameter set to use for this
        encryption. Must match a level the recipient's ML-KEM keypair
        actually supports.

    Raises
    ------
    TypeError
        If `plaintext` is not bytes-like or `recipient_public_key` is not a
        HybridPublicKey.
    FileEncryptorError
        If hybrid key establishment against `recipient_public_key` fails
        (e.g. malformed public key material).
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError(f"plaintext must be bytes, got {type(plaintext).__name__}")
    if not isinstance(recipient_public_key, HybridPublicKey):
        raise TypeError(
            "recipient_public_key must be a HybridPublicKey, got "
            f"{type(recipient_public_key).__name__}"
        )

    exchange = HybridKeyExchange(ml_kem_security_level)
    try:
        kem_ciphertext, session_key = exchange.initiate(recipient_public_key)
    except HybridKeyExchangeError as exc:
        raise FileEncryptorError(f"hybrid key establishment failed: {exc}") from exc

    file_key = _derive_file_key(session_key)

    package_without_ciphertext = EncryptedFilePackage(
        version=FORMAT_VERSION,
        kdf_algorithm="HKDF-SHA256",
        aead_algorithm="AES-256-GCM",
        classical_algorithm=kem_ciphertext.classical_algorithm,
        ml_kem_security_level=kem_ciphertext.ml_kem_security_level,
        classical_ciphertext=kem_ciphertext.classical_ciphertext,
        pq_ciphertext=kem_ciphertext.pq_ciphertext,
        nonce=b"",
        ciphertext=b"",
    )
    aad = package_without_ciphertext.associated_data()
    sealed = aes.encrypt(bytes(plaintext), file_key, associated_data=aad)

    return EncryptedFilePackage(
        version=FORMAT_VERSION,
        kdf_algorithm="HKDF-SHA256",
        aead_algorithm="AES-256-GCM",
        classical_algorithm=kem_ciphertext.classical_algorithm,
        ml_kem_security_level=kem_ciphertext.ml_kem_security_level,
        classical_ciphertext=kem_ciphertext.classical_ciphertext,
        pq_ciphertext=kem_ciphertext.pq_ciphertext,
        nonce=sealed.nonce,
        ciphertext=sealed.ciphertext,
    )


def _derive_file_key(session_key: bytes) -> bytes:
    return derive_key(session_key, aes.KEY_SIZE, info=FILE_ENCRYPTION_KDF_CONTEXT)
