"""
signatures.py -- hybrid digital signatures (ML-DSA + classical)
====================================================================

GOAL
------
Demonstrate a transition-period design where authenticity requires BOTH a
post-quantum signature and a classical signature to verify:

                     message
                        |
              +---------+---------+
              v                   v
           ML-DSA               Ed25519
              |                   |
              v                   v
         PQ signature      classical signature
              |                   |
              +---------+---------+
                        v
                 hybrid signature

DEFAULT VERIFICATION POLICY: ML-DSA valid AND classical valid. A signature
that only satisfies one of the two algorithms is NOT accepted -- there is no
partial-credit fallback, and a failed PQ signature is never masked by a
successful classical one (or vice versa). This is deliberate: during the
transition period neither algorithm is assumed sufficient on its own to trust
completely, so both gates must pass.

WHAT THIS DOES NOT CLAIM
---------------------------
Requiring both signatures to verify is a straightforward, explicit
composition, not a formally proven hybrid-signature security theorem for
every possible algorithm pairing. See docs/security_analysis.md.

`HybridSignature` carries explicit algorithm/version identifiers
(`ml_dsa_security_level`, `classical_algorithm`, `version`) rather than being
a bare concatenation of two byte strings, so `verify()` can reject a
structurally wrong or mismatched-version signature package outright.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcrypto.signatures.classical_signature import ClassicalSignature
from pqcrypto.signatures.ml_dsa import MLDSA

FORMAT_VERSION = 1


class HybridSignatureError(ValueError):
    """Raised for malformed key material passed to HybridSigner, or invalid
    types passed where a HybridSignature*/HybridSignatureSecretKeys is expected."""


@dataclass(frozen=True)
class HybridSignaturePublicKeys:
    """The public half of a hybrid signing identity -- hand this out to verifiers."""

    ml_dsa_public_key: bytes
    classical_public_key: bytes


@dataclass(frozen=True)
class HybridSignatureSecretKeys:
    """The secret half of a hybrid signing identity -- never transmit or log this."""

    ml_dsa_secret_key: bytes
    classical_secret_key: bytes


@dataclass(frozen=True)
class HybridSignature:
    """A message's ML-DSA signature and classical signature, bundled with the
    identifiers needed to verify them without positional assumptions."""

    ml_dsa_signature: bytes
    classical_signature: bytes
    ml_dsa_security_level: int
    classical_algorithm: str
    version: int = FORMAT_VERSION


class HybridSigner:
    """Hybrid ML-DSA + Ed25519 signing and verification.

    Example
    -------
    >>> signer = HybridSigner(65)
    >>> public_keys, secret_keys = signer.generate_keypairs()
    >>> signature = signer.sign(b"hello", secret_keys)
    >>> signer.verify(b"hello", signature, public_keys)
    True
    """

    def __init__(self, ml_dsa_security_level: int = 65) -> None:
        self._pq = MLDSA(ml_dsa_security_level)
        self._classical = ClassicalSignature()

    def generate_keypairs(
        self,
    ) -> tuple[HybridSignaturePublicKeys, HybridSignatureSecretKeys]:
        """Generate one ML-DSA keypair and one Ed25519 keypair, bundled together."""
        pq_public, pq_secret = self._pq.generate_keypair()
        classical_public, classical_secret = self._classical.generate_keypair()
        return (
            HybridSignaturePublicKeys(pq_public, classical_public),
            HybridSignatureSecretKeys(pq_secret, classical_secret),
        )

    def sign(self, message: bytes, secret_keys: HybridSignatureSecretKeys) -> HybridSignature:
        """Sign `message` with BOTH algorithms, returning the combined signature.

        Raises
        ------
        TypeError
            If `message` isn't bytes-like or `secret_keys` isn't a
            HybridSignatureSecretKeys.
        MLDSAError / ClassicalSignatureError
            If either secret key has the wrong length for this instance's
            configured security level/algorithm.
        """
        if not isinstance(secret_keys, HybridSignatureSecretKeys):
            raise TypeError(
                f"secret_keys must be HybridSignatureSecretKeys, got {type(secret_keys).__name__}"
            )
        pq_signature = self._pq.sign(message, secret_keys.ml_dsa_secret_key)
        classical_signature = self._classical.sign(message, secret_keys.classical_secret_key)
        return HybridSignature(
            ml_dsa_signature=pq_signature,
            classical_signature=classical_signature,
            ml_dsa_security_level=self._pq.security_level,
            classical_algorithm=self._classical.algorithm_name,
        )

    def verify(
        self,
        message: bytes,
        signature: HybridSignature,
        public_keys: HybridSignaturePublicKeys,
    ) -> bool:
        """Verify `signature` over `message` under `public_keys`.

        Returns True only if BOTH the ML-DSA signature and the classical
        signature independently verify, AND the signature's algorithm
        identifiers/version match this instance's configuration. Returns
        False for every other case -- wrong/tampered message, either
        signature component tampered, wrong public key(s), a mismatched
        algorithm identifier, or a mismatched version. This method is a
        total function over well-typed input: it never raises for
        adversarial-but-correctly-typed `signature`/`public_keys` field
        contents, only for wrong Python types.

        Raises
        ------
        TypeError
            If `message` isn't bytes-like, or `signature`/`public_keys` isn't
            the expected dataclass type.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(f"message must be bytes, got {type(message).__name__}")
        if not isinstance(signature, HybridSignature):
            raise TypeError(f"signature must be a HybridSignature, got {type(signature).__name__}")
        if not isinstance(public_keys, HybridSignaturePublicKeys):
            raise TypeError(
                f"public_keys must be HybridSignaturePublicKeys, got {type(public_keys).__name__}"
            )

        # Structural/identifier checks fail safely (False), never raise --
        # an attacker-controlled signature package with a bogus version or
        # algorithm name must be rejected the same way a bad signature is.
        if signature.version != FORMAT_VERSION:
            return False
        if signature.ml_dsa_security_level != self._pq.security_level:
            return False
        if signature.classical_algorithm != self._classical.algorithm_name:
            return False

        pq_ok = self._pq.verify(message, signature.ml_dsa_signature, public_keys.ml_dsa_public_key)
        classical_ok = self._classical.verify(
            message, signature.classical_signature, public_keys.classical_public_key
        )
        # Explicit AND, computed from both independent results -- a failed
        # PQ signature is never allowed to be masked by a successful
        # classical one, or vice versa.
        return pq_ok and classical_ok

    def __repr__(self) -> str:
        return (
            f"HybridSigner(ml_dsa_security_level={self._pq.security_level}, "
            f"classical_algorithm={self._classical.algorithm_name!r})"
        )
