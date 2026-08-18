"""
classical_signature.py -- classical digital signature wrapper (Ed25519)
===========================================================================

PURPOSE
---------
Provides the classical half of this project's signature comparison and
hybrid signatures (see pqcrypto.hybrid.signatures), using an established
classical signature algorithm from `cryptography` (pyca) rather than any
hand-rolled implementation.

WHY Ed25519?
--------------
Ed25519 (EdDSA over Curve25519, RFC 8032) was chosen over RSA or "plain"
ECDSA for several concrete reasons relevant to this project:
  * Fixed-size, small keys (32 bytes) and signatures (64 bytes) -- comparable
    in spirit to how ML-DSA reports fixed sizes, making benchmark comparisons
    cleaner than against RSA's much larger, security-level-dependent keys.
  * Deterministic signing: unlike classical ECDSA, Ed25519 does not require
    the caller to supply fresh per-signature randomness, eliminating an
    entire historical class of real-world key-recovery bugs caused by nonce
    reuse or poor-quality randomness in ECDSA implementations.
  * Modern, widely reviewed, and directly supported by `cryptography` with a
    clean raw-bytes API.

SECURITY NOTE -- QUANTUM VULNERABILITY
------------------------------------------
Ed25519's security rests on the elliptic-curve discrete logarithm problem
over Curve25519. Shor's algorithm solves discrete logarithms efficiently on a
sufficiently large quantum computer, which would break Ed25519 completely
(recover the secret key from the public key). This is exactly the threat
ML-DSA is designed to resist instead. Ed25519 is included here ONLY as a
classical baseline for comparison and as one half of the hybrid signature
scheme in pqcrypto.hybrid.signatures -- never as a quantum-resistant
component on its own.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PUBLIC_KEY_SIZE = 32
SECRET_KEY_SIZE = 32
SIGNATURE_SIZE = 64
ALGORITHM_NAME = "Ed25519"


class ClassicalSignatureError(ValueError):
    """Raised for malformed classical-signature key material."""


class ClassicalSignature:
    """A thin wrapper around Ed25519, matching MLDSA's method shape.

    Example
    -------
    >>> sig = ClassicalSignature()
    >>> public_key, secret_key = sig.generate_keypair()
    >>> signature = sig.sign(b"hello", secret_key)
    >>> sig.verify(b"hello", signature, public_key)
    True
    """

    public_key_size = PUBLIC_KEY_SIZE
    secret_key_size = SECRET_KEY_SIZE
    signature_size = SIGNATURE_SIZE
    algorithm_name = ALGORITHM_NAME

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Create a fresh (public_key, secret_key) pair, as raw 32-byte values."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        secret_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return public_bytes, secret_bytes

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign `message` with `secret_key`, returning a 64-byte signature.

        Raises
        ------
        TypeError
            If `message` or `secret_key` is not bytes/bytearray.
        ClassicalSignatureError
            If `secret_key` is not exactly SECRET_KEY_SIZE bytes.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(f"message must be bytes, got {type(message).__name__}")
        self._validate_key("secret_key", secret_key, SECRET_KEY_SIZE)
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(secret_key))
        return private_key.sign(bytes(message))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify `signature` over `message` under `public_key`.

        Returns True only for a valid signature; False for every other case.
        Like MLDSA.verify, this is a total function over well-typed input --
        it never raises for adversarial-but-correctly-typed `signature` bytes.

        Raises
        ------
        TypeError
            If `message`, `signature`, or `public_key` is not bytes/bytearray.
        ClassicalSignatureError
            If `public_key` is not exactly PUBLIC_KEY_SIZE bytes.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(f"message must be bytes, got {type(message).__name__}")
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError(f"signature must be bytes, got {type(signature).__name__}")
        self._validate_key("public_key", public_key, PUBLIC_KEY_SIZE)

        try:
            public = Ed25519PublicKey.from_public_bytes(bytes(public_key))
            public.verify(bytes(signature), bytes(message))
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Malformed signature bytes (wrong length, etc.) must be treated
            # as "does not verify", not surfaced as a crash -- see MLDSA.verify
            # for the same reasoning.
            return False

    @staticmethod
    def _validate_key(name: str, value: object, expected_size: int) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
        if len(value) != expected_size:
            raise ClassicalSignatureError(
                f"{name} has invalid length: expected {expected_size} bytes, "
                f"got {len(value)}"
            )

    def __repr__(self) -> str:
        return f"ClassicalSignature(algorithm={ALGORITHM_NAME!r})"
