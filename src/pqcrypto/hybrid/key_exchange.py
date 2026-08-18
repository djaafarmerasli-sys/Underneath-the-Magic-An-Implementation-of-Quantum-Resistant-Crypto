"""
key_exchange.py -- hybrid classical + post-quantum key establishment
=========================================================================

GOAL
------
Demonstrate the transition-period hybrid design:

    classical (X25519) shared secret
                    +
      ML-KEM shared secret
                    |
                   KDF
                    |
            final session key

Both components are independently established, then combined by
pqcrypto.hybrid.kdf.derive_hybrid_session_key. The point of running BOTH is
that the final session key stays secret as long as AT LEAST ONE of the two
underlying mechanisms remains unbroken -- if a future quantum computer breaks
X25519, ML-KEM alone still protects the session key, and vice versa if some
future cryptanalytic advance weakens ML-KEM.

IMPORTANT -- WHAT THIS DOES NOT CLAIM
----------------------------------------
Concatenating two independently-established secrets through an HKDF
combiner (this project's approach, and the same shape used in TLS 1.3's
hybrid key exchange) is a standard, widely-used construction -- but this
project does NOT claim it is a formally proven hybrid-secure composition for
every possible pairing of algorithms. See docs/security_analysis.md for the
composition assumptions this makes explicit rather than glosses over.

WHY TYPED WRAPPER OBJECTS, NOT RAW TUPLES?
-----------------------------------------------
HybridPublicKey / HybridSecretKey / HybridCiphertext are small frozen
dataclasses, not bare `bytes` or positional tuples. This makes it structurally
harder to, say, pass a classical secret key where the PQ secret key was
expected -- the wrong dataclass simply doesn't have the field being accessed,
so a mismatch is caught immediately rather than silently producing a garbage
session key. HybridCiphertext also carries explicit algorithm identifiers
(`classical_algorithm`, `ml_kem_security_level`) and a `version`, so a
recipient validates compatibility BEFORE attempting to derive a key from it --
there is no silent classical-only or PQ-only fallback if one component is
missing or mismatched; both must be present and valid, or `respond()` raises.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcrypto.hybrid.kdf import derive_hybrid_session_key
from pqcrypto.kem.classical_kem import ClassicalKEM, ClassicalKEMError
from pqcrypto.kem.ml_kem import MLKEM, MLKEMError

FORMAT_VERSION = 1


class HybridKeyExchangeError(ValueError):
    """Raised for incomplete handshake data or an algorithm/version mismatch
    between a HybridCiphertext and the HybridKeyExchange instance processing it."""


@dataclass(frozen=True)
class HybridPublicKey:
    """The public half of a hybrid keypair -- hand this out to senders."""

    classical_public_key: bytes
    pq_public_key: bytes


@dataclass(frozen=True)
class HybridSecretKey:
    """The secret half of a hybrid keypair -- never transmit or log this."""

    classical_secret_key: bytes
    pq_secret_key: bytes


@dataclass(frozen=True)
class HybridCiphertext:
    """Everything a recipient needs, alongside their HybridSecretKey, to
    derive the same session key the sender derived. Contains no secret
    material of its own -- both ciphertext components are meant to be sent
    over the (public) wire."""

    classical_ciphertext: bytes
    pq_ciphertext: bytes
    classical_algorithm: str
    ml_kem_security_level: int
    version: int = FORMAT_VERSION


class HybridKeyExchange:
    """Hybrid X25519 + ML-KEM key establishment.

    Example
    -------
    >>> alice = HybridKeyExchange(768)
    >>> bob = HybridKeyExchange(768)
    >>> bob_public, bob_secret = bob.generate_keypair()
    >>> ciphertext, alice_key = alice.initiate(bob_public)
    >>> bob_key = bob.respond(bob_secret, ciphertext)
    >>> alice_key == bob_key
    True
    """

    def __init__(self, ml_kem_security_level: int = 768) -> None:
        self._classical = ClassicalKEM()
        self._pq = MLKEM(ml_kem_security_level)

    def generate_keypair(self) -> tuple[HybridPublicKey, HybridSecretKey]:
        """Generate one X25519 keypair and one ML-KEM keypair, bundled together."""
        classical_public, classical_secret = self._classical.generate_keypair()
        pq_public, pq_secret = self._pq.generate_keypair()
        return (
            HybridPublicKey(classical_public, pq_public),
            HybridSecretKey(classical_secret, pq_secret),
        )

    def initiate(self, recipient_public_key: HybridPublicKey) -> tuple[HybridCiphertext, bytes]:
        """INITIATOR/SENDER side: encapsulate to both components and derive
        the session key.

        Returns (ciphertext, session_key). Transmit `ciphertext` to the
        recipient; keep `session_key` as the shared AES-256 key.
        """
        if not isinstance(recipient_public_key, HybridPublicKey):
            raise TypeError(
                "recipient_public_key must be a HybridPublicKey, got "
                f"{type(recipient_public_key).__name__}"
            )
        try:
            classical_ciphertext, classical_secret = self._classical.encapsulate(
                recipient_public_key.classical_public_key
            )
        except (TypeError, ClassicalKEMError) as exc:
            raise HybridKeyExchangeError(f"classical encapsulation failed: {exc}") from exc
        try:
            pq_ciphertext, pq_secret = self._pq.encapsulate(recipient_public_key.pq_public_key)
        except (TypeError, MLKEMError) as exc:
            raise HybridKeyExchangeError(f"ML-KEM encapsulation failed: {exc}") from exc

        session_key = derive_hybrid_session_key(classical_secret, pq_secret)
        ciphertext = HybridCiphertext(
            classical_ciphertext=classical_ciphertext,
            pq_ciphertext=pq_ciphertext,
            classical_algorithm=self._classical.algorithm_name,
            ml_kem_security_level=self._pq.security_level,
        )
        return ciphertext, session_key

    def respond(self, secret_key: HybridSecretKey, ciphertext: HybridCiphertext) -> bytes:
        """RECIPIENT/RESPONDER side: decapsulate both components and derive
        the SAME session key `initiate()` produced.

        Raises
        ------
        TypeError
            If `secret_key`/`ciphertext` aren't the expected dataclasses.
        HybridKeyExchangeError
            If the ciphertext's format version or algorithm identifiers don't
            match this instance (no silent downgrade to either component
            alone), or if either component fails to decapsulate.
        """
        if not isinstance(secret_key, HybridSecretKey):
            raise TypeError(f"secret_key must be a HybridSecretKey, got {type(secret_key).__name__}")
        if not isinstance(ciphertext, HybridCiphertext):
            raise TypeError(f"ciphertext must be a HybridCiphertext, got {type(ciphertext).__name__}")
        if ciphertext.version != FORMAT_VERSION:
            raise HybridKeyExchangeError(
                f"unsupported hybrid key-exchange format version {ciphertext.version!r} "
                f"(expected {FORMAT_VERSION})"
            )
        if ciphertext.classical_algorithm != self._classical.algorithm_name:
            raise HybridKeyExchangeError(
                f"classical algorithm mismatch: ciphertext uses "
                f"{ciphertext.classical_algorithm!r}, this instance expects "
                f"{self._classical.algorithm_name!r}"
            )
        if ciphertext.ml_kem_security_level != self._pq.security_level:
            raise HybridKeyExchangeError(
                f"ML-KEM security level mismatch: ciphertext uses "
                f"{ciphertext.ml_kem_security_level}, this instance expects "
                f"{self._pq.security_level}"
            )

        try:
            classical_secret = self._classical.decapsulate(
                secret_key.classical_secret_key, ciphertext.classical_ciphertext
            )
        except (TypeError, ClassicalKEMError) as exc:
            raise HybridKeyExchangeError(f"classical decapsulation failed: {exc}") from exc
        try:
            pq_secret = self._pq.decapsulate(secret_key.pq_secret_key, ciphertext.pq_ciphertext)
        except (TypeError, MLKEMError) as exc:
            raise HybridKeyExchangeError(f"ML-KEM decapsulation failed: {exc}") from exc

        return derive_hybrid_session_key(classical_secret, pq_secret)
