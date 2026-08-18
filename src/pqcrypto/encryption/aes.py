"""
aes.py -- AES-256-GCM authenticated encryption for pqcrypto
===============================================================

WHY AES-GCM, AND WHY NOT ML-KEM?
----------------------------------
ML-KEM is a Key Encapsulation Mechanism: it lets two parties agree on a small
(32-byte) shared secret. It is NOT designed to encrypt bulk data, has no
notion of "plaintext" as an argument, and would be catastrophically slow and
size-inefficient if it were repurposed that way (lattice-based ciphertexts
are hundreds to thousands of bytes for 32 bytes of payload).

The standard pattern -- and the one this project follows -- is: use an
asymmetric mechanism (ML-KEM, or the hybrid combination in
pqcrypto.hybrid.key_exchange) only to establish a *symmetric* key, then
encrypt the actual data with a fast, well-understood symmetric cipher. AES-256
is that cipher here. AES is a block cipher, not quantum-broken the way RSA/
ECC are: Grover's algorithm gives a quantum computer at best a quadratic
speedup against AES's 2^256 keyspace, which AES-256's margin already absorbs
(effectively ~2^128 quantum security, still infeasible).

WHY GCM, SPECIFICALLY?
------------------------
Plain AES (e.g. CBC mode) provides confidentiality only -- a tampered
ciphertext will just decrypt to different garbage plaintext with NO error,
which is a classic source of real-world vulnerabilities (padding-oracle
attacks, silent corruption). AES-GCM is an AEAD (Authenticated Encryption
with Associated Data) mode: it produces a ciphertext bundled with an
authentication tag, and decryption CRYPTOGRAPHICALLY VERIFIES that tag before
returning any plaintext. Any modification to the ciphertext, the nonce, or
the associated data causes decryption to fail outright rather than return
corrupted-but-unflagged data. This project uses AES-GCM exclusively; it never
uses an unauthenticated mode.

NONCE DISCIPLINE
-----------------
AES-GCM's security guarantee collapses if the same (key, nonce) pair is ever
reused -- it can leak the authentication key and allow forgery. `encrypt()`
therefore generates a fresh, cryptographically random 96-bit (12-byte) nonce
on every call via pqcrypto.utils.randomness, and always returns it bundled
with the ciphertext (see AESGCMCiphertext) so a caller cannot accidentally
"lose" the nonce and later decrypt with a mismatched or reused one.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcrypto.utils import randomness

KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # 96 bits -- the size AES-GCM is specified and optimized for
TAG_SIZE = 16  # 128-bit authentication tag, appended to the ciphertext by AESGCM


class AESGCMError(ValueError):
    """Raised for invalid key/nonce material passed to encrypt()/decrypt()."""


class AuthenticationError(AESGCMError):
    """Raised when decryption's integrity check fails.

    Covers a tampered ciphertext, a tampered/incorrect nonce, tampered or
    mismatched associated data, or simply the wrong key -- AES-GCM's tag
    verification cannot and does not distinguish between these causes, and
    deliberately does not report which one occurred (that itself can leak
    information to an attacker probing the scheme).
    """


@dataclass(frozen=True)
class AESGCMCiphertext:
    """The nonce and ciphertext (tag included) from one encrypt() call.

    Bundling these together -- rather than returning a bare `bytes` and
    expecting the caller to track the nonce separately -- makes it
    structurally harder to accidentally decrypt with a mismatched nonce or
    forget to persist it alongside the ciphertext.
    """

    nonce: bytes
    ciphertext: bytes  # AESGCM appends the 16-byte tag; this already includes it


def encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> AESGCMCiphertext:
    """Encrypt `plaintext` under `key`, authenticating `associated_data` too.

    `associated_data` (AAD) is authenticated but NOT encrypted -- it travels
    alongside the ciphertext in the clear, and decryption fails if it doesn't
    match exactly what was supplied here. Use it for context that must be
    bound to this ciphertext but doesn't need confidentiality, e.g. a format
    version or algorithm identifier (see file_encryptor.py).

    Raises
    ------
    TypeError
        If `plaintext`/`key`/`associated_data` isn't bytes-like.
    AESGCMError
        If `key` is not exactly 32 bytes (AES-256 only -- this wrapper never
        silently accepts AES-128/192).
    """
    _validate_bytes("plaintext", plaintext)
    _validate_key(key)
    if associated_data is not None:
        _validate_bytes("associated_data", associated_data)

    nonce = randomness.random_bytes(NONCE_SIZE)
    aesgcm = AESGCM(bytes(key))
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), bytes(associated_data) if associated_data else None)
    return AESGCMCiphertext(nonce=nonce, ciphertext=ciphertext)


def decrypt(
    package: AESGCMCiphertext,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate `package`, returning plaintext only on success.

    Plaintext is returned ONLY if the authentication tag verifies against the
    given key, nonce, ciphertext, AND associated_data. Any mismatch --
    tampered ciphertext, tampered nonce, wrong/mismatched associated_data, or
    the wrong key -- raises AuthenticationError. There is no code path that
    returns unauthenticated plaintext; a failed check never degrades into a
    "best effort" result.

    Raises
    ------
    TypeError
        If `package.nonce`/`package.ciphertext`/`key`/`associated_data` isn't
        bytes-like, or `package` isn't an AESGCMCiphertext.
    AESGCMError
        If `key` is not exactly 32 bytes, or `package.nonce` is not exactly
        NONCE_SIZE bytes.
    AuthenticationError
        If authentication fails for any reason (see above).
    """
    if not isinstance(package, AESGCMCiphertext):
        raise TypeError(f"package must be an AESGCMCiphertext, got {type(package).__name__}")
    _validate_key(key)
    _validate_bytes("package.nonce", package.nonce)
    if len(package.nonce) != NONCE_SIZE:
        raise AESGCMError(
            f"package.nonce has invalid length: expected {NONCE_SIZE} bytes, "
            f"got {len(package.nonce)}"
        )
    _validate_bytes("package.ciphertext", package.ciphertext)
    if associated_data is not None:
        _validate_bytes("associated_data", associated_data)

    aesgcm = AESGCM(bytes(key))
    try:
        return aesgcm.decrypt(
            bytes(package.nonce),
            bytes(package.ciphertext),
            bytes(associated_data) if associated_data else None,
        )
    except InvalidTag as exc:
        raise AuthenticationError(
            "AES-GCM authentication failed: ciphertext, nonce, associated data, "
            "or key is incorrect"
        ) from exc


def _validate_key(key: bytes) -> None:
    _validate_bytes("key", key)
    if len(key) != KEY_SIZE:
        raise AESGCMError(f"key must be exactly {KEY_SIZE} bytes (AES-256), got {len(key)}")


def _validate_bytes(name: str, value: object) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
