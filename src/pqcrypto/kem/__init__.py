"""Key Encapsulation Mechanisms (KEMs) for pqcrypto.

A KEM lets two parties agree on a shared secret over a public channel. This
package exposes the post-quantum ML-KEM (FIPS 203, historically
CRYSTALS-Kyber) wrapper and a classical X25519-based KEM baseline used for
benchmark comparison and as the classical half of the hybrid key exchange in
pqcrypto.hybrid.key_exchange.
"""

from .classical_kem import ClassicalKEM
from .ml_kem import MLKEM

__all__ = ["MLKEM", "ClassicalKEM"]
