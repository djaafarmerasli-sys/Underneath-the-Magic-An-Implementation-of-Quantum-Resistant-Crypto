"""
file_decryptor.py -- high-level hybrid file decryption
==========================================================

The inverse of pqcrypto.encryption.file_encryptor. Given an
EncryptedFilePackage and the recipient's HybridSecretKey, reproduces every
step of encryption in reverse:

    EncryptedFilePackage
        |
        v
    validate version + algorithm identifiers        (before trusting anything)
        |
        v
    hybrid key recovery (X25519 + ML-KEM decapsulation)
        |
        v
    KDF  ->  the SAME AES-256 key encrypt_file() derived
        |
        v
    AES-256-GCM authenticate + decrypt
        |
        v
    plaintext                                        (ONLY on success)

CRITICAL INVARIANT: this module never returns plaintext unless AES-GCM's
authentication tag has verified. There is no partial/best-effort decryption
path. Every failure mode below -- an unsupported version, an unrecognized
algorithm identifier, a malformed or wrong-length KEM ciphertext, a wrong
secret key, or a tampered ciphertext/nonce/associated-data -- raises
FileDecryptorError (or a TypeError for a plain wrong-Python-type argument)
instead of returning corrupted or unauthenticated bytes.

VERSION & ALGORITHM VALIDATION
-----------------------------------
`decrypt_file` checks `package.version` and the declared KDF/AEAD algorithm
identifiers itself, BEFORE attempting any key recovery -- an unsupported
combination is rejected immediately rather than discovered later as a
confusing authentication failure. This is also where a future version of
this project would branch to support additional algorithm choices without
breaking compatibility with packages produced by this version.
"""

from __future__ import annotations

from pqcrypto.encryption import aes
from pqcrypto.encryption.file_encryptor import (
    FILE_ENCRYPTION_KDF_CONTEXT,
    FORMAT_VERSION,
    EncryptedFilePackage,
)
from pqcrypto.hybrid.kdf import derive_key
from pqcrypto.hybrid.key_exchange import (
    HybridCiphertext,
    HybridKeyExchange,
    HybridKeyExchangeError,
    HybridSecretKey,
)

_SUPPORTED_KDF_ALGORITHMS = {"HKDF-SHA256"}
_SUPPORTED_AEAD_ALGORITHMS = {"AES-256-GCM"}


class FileDecryptorError(ValueError):
    """Raised for an unsupported package version/algorithm, malformed package
    fields, failed hybrid key recovery, or failed AES-GCM authentication.

    Deliberately a single exception type for every "this package cannot be
    decrypted" outcome -- the specific cause (wrong key vs. tampered bytes
    vs. unsupported version) is included in the message for debugging, but
    callers checking "did decryption succeed" need only catch one type.
    """


def decrypt_file(package: EncryptedFilePackage, secret_key: HybridSecretKey) -> bytes:
    """Authenticate and decrypt `package`, returning plaintext ONLY on success.

    Parameters
    ----------
    package : the EncryptedFilePackage produced by
        pqcrypto.encryption.file_encryptor.encrypt_file (or reconstructed via
        EncryptedFilePackage.from_bytes from serialized data -- either way,
        every field here is untrusted until authentication succeeds).
    secret_key : the recipient's HybridSecretKey, matching the
        HybridPublicKey `package` was encrypted against.

    Raises
    ------
    TypeError
        If `package` is not an EncryptedFilePackage or `secret_key` is not a
        HybridSecretKey.
    FileDecryptorError
        If the package's format version or declared KDF/AEAD algorithm is
        unsupported; if the package's ML-KEM security level is invalid; if
        hybrid key recovery fails (malformed KEM ciphertext, or a
        `secret_key` that doesn't match the classical/ML-KEM algorithm the
        package declares); or if AES-GCM authentication fails for any reason
        (wrong key, tampered nonce/ciphertext/associated-data). This last
        case covers a `secret_key` that IS the right algorithm/shape but the
        wrong identity -- hybrid decapsulation itself won't raise for that
        (see ML-KEM's implicit rejection in pqcrypto.kem.ml_kem), so the
        mismatch only becomes visible here, at the AEAD authentication step.
    """
    if not isinstance(package, EncryptedFilePackage):
        raise TypeError(f"package must be an EncryptedFilePackage, got {type(package).__name__}")
    if not isinstance(secret_key, HybridSecretKey):
        raise TypeError(f"secret_key must be a HybridSecretKey, got {type(secret_key).__name__}")

    if package.version != FORMAT_VERSION:
        raise FileDecryptorError(
            f"unsupported encrypted-file format version {package.version!r} "
            f"(expected {FORMAT_VERSION})"
        )
    if package.kdf_algorithm not in _SUPPORTED_KDF_ALGORITHMS:
        raise FileDecryptorError(f"unsupported KDF algorithm {package.kdf_algorithm!r}")
    if package.aead_algorithm not in _SUPPORTED_AEAD_ALGORITHMS:
        raise FileDecryptorError(f"unsupported AEAD algorithm {package.aead_algorithm!r}")

    try:
        exchange = HybridKeyExchange(package.ml_kem_security_level)
    except ValueError as exc:
        raise FileDecryptorError(f"unsupported ML-KEM security level in package: {exc}") from exc

    kem_ciphertext = HybridCiphertext(
        classical_ciphertext=package.classical_ciphertext,
        pq_ciphertext=package.pq_ciphertext,
        classical_algorithm=package.classical_algorithm,
        ml_kem_security_level=package.ml_kem_security_level,
    )
    try:
        session_key = exchange.respond(secret_key, kem_ciphertext)
    except HybridKeyExchangeError as exc:
        raise FileDecryptorError(f"hybrid key recovery failed: {exc}") from exc

    file_key = derive_key(session_key, aes.KEY_SIZE, info=FILE_ENCRYPTION_KDF_CONTEXT)

    sealed = aes.AESGCMCiphertext(nonce=package.nonce, ciphertext=package.ciphertext)
    try:
        return aes.decrypt(sealed, file_key, associated_data=package.associated_data())
    except aes.AESGCMError as exc:
        raise FileDecryptorError(f"file decryption failed: {exc}") from exc
