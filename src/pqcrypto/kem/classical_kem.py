"""
classical_kem.py -- classical KEM-shaped wrapper around X25519 (DHKEM)
==========================================================================

PURPOSE
---------
Provides the classical half of this project's KEM comparison and hybrid key
exchange (see pqcrypto.hybrid.key_exchange), exposing X25519 Diffie-Hellman
through the SAME generate_keypair / encapsulate / decapsulate shape as
MLKEM -- so the two can be benchmarked side by side and combined mechanically
in the hybrid layer without special-casing either one.

X25519 itself is a key-AGREEMENT primitive, not a KEM: both sides normally
run their own local Diffie-Hellman computation from a static or ephemeral
keypair. To fit the KEM interface, this wrapper uses the standard "DHKEM"
construction (the same approach RFC 9180 / HPKE uses):

    encapsulate(recipient_public_key):
        1. generate a fresh EPHEMERAL X25519 keypair
        2. Diffie-Hellman the ephemeral secret with the recipient's public key
        3. return (ephemeral_public_key, shared_secret)
                    ^ this is the "ciphertext"

    decapsulate(secret_key, ciphertext):
        1. treat `ciphertext` as the sender's ephemeral public key
        2. Diffie-Hellman it with the recipient's own secret key
        3. return the same shared_secret (X25519 is symmetric: both sides
           compute the identical value from swapped key pairs)

SECURITY NOTES
----------------
* Shor's algorithm breaks X25519 (elliptic-curve discrete log) on a
  sufficiently large quantum computer. This wrapper exists ONLY for
  benchmarking comparison and as the classical component of the hybrid key
  exchange -- never as a quantum-resistant mechanism on its own.
* The raw X25519 shared secret is NOT a uniformly random key suitable for
  direct use as an AES key -- it MUST be passed through a KDF first (see
  pqcrypto.hybrid.kdf). This wrapper returns the raw ECDH output verbatim and
  never uses it for encryption itself.
* Per RFC 7748 SS6.1, we reject an all-zero shared secret. This is the known
  X25519 "contributory behaviour" pitfall: certain low-order public key
  inputs can force the ECDH output to all-zero bytes regardless of the other
  party's secret key. Rejecting it is the standard mitigation.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PUBLIC_KEY_SIZE = 32
SECRET_KEY_SIZE = 32
CIPHERTEXT_SIZE = 32  # the sender's ephemeral public key
SHARED_SECRET_SIZE = 32
ALGORITHM_NAME = "X25519"

_ALL_ZERO_SECRET = b"\x00" * SHARED_SECRET_SIZE


class ClassicalKEMError(ValueError):
    """Raised for malformed classical KEM key/ciphertext material, or a
    degenerate (all-zero) Diffie-Hellman result -- see module docstring."""


class ClassicalKEM:
    """A KEM-shaped wrapper around X25519, matching MLKEM's method shape.

    Example
    -------
    >>> kem = ClassicalKEM()
    >>> public_key, secret_key = kem.generate_keypair()
    >>> ciphertext, secret_sender = kem.encapsulate(public_key)
    >>> secret_recipient = kem.decapsulate(secret_key, ciphertext)
    >>> secret_sender == secret_recipient
    True
    """

    public_key_size = PUBLIC_KEY_SIZE
    secret_key_size = SECRET_KEY_SIZE
    ciphertext_size = CIPHERTEXT_SIZE
    shared_secret_size = SHARED_SECRET_SIZE
    algorithm_name = ALGORITHM_NAME

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Create a fresh (public_key, secret_key) pair, as raw 32-byte values."""
        secret_key = X25519PrivateKey.generate()
        public_key = secret_key.public_key()
        secret_bytes = secret_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return public_bytes, secret_bytes

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """SENDER side: DHKEM against the recipient's public key.

        Returns (ciphertext, shared_secret) -- `ciphertext` here is the
        sender's freshly generated ephemeral public key, matching MLKEM's
        return shape.
        """
        self._validate("public_key", public_key, PUBLIC_KEY_SIZE)
        ephemeral_secret = X25519PrivateKey.generate()
        ephemeral_public_bytes = ephemeral_secret.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        recipient_public = X25519PublicKey.from_public_bytes(bytes(public_key))
        shared_secret = ephemeral_secret.exchange(recipient_public)
        self._reject_degenerate(shared_secret)
        return ephemeral_public_bytes, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """RECIPIENT side: recover the same shared secret from the sender's
        ephemeral public key (`ciphertext`)."""
        self._validate("secret_key", secret_key, SECRET_KEY_SIZE)
        self._validate("ciphertext", ciphertext, CIPHERTEXT_SIZE)
        own_secret = X25519PrivateKey.from_private_bytes(bytes(secret_key))
        ephemeral_public = X25519PublicKey.from_public_bytes(bytes(ciphertext))
        shared_secret = own_secret.exchange(ephemeral_public)
        self._reject_degenerate(shared_secret)
        return shared_secret

    @staticmethod
    def _reject_degenerate(shared_secret: bytes) -> None:
        if shared_secret == _ALL_ZERO_SECRET:
            raise ClassicalKEMError(
                "X25519 produced an all-zero shared secret -- indicates an "
                "invalid or low-order public key (see RFC 7748 SS6.1)"
            )

    @staticmethod
    def _validate(name: str, value: object, expected_size: int) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
        if len(value) != expected_size:
            raise ClassicalKEMError(
                f"{name} has invalid length: expected {expected_size} bytes, "
                f"got {len(value)}"
            )

    def __repr__(self) -> str:
        return f"ClassicalKEM(algorithm={ALGORITHM_NAME!r})"
