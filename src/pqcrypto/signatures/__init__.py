"""Digital signature algorithms for pqcrypto.

Exposes the post-quantum ML-DSA (FIPS 204, historically CRYSTALS-Dilithium)
wrapper and a classical Ed25519 signature baseline used for benchmark
comparison and as the classical half of the hybrid signatures in
pqcrypto.hybrid.signatures.
"""

from .classical_signature import ClassicalSignature
from .ml_dsa import MLDSA

__all__ = ["MLDSA", "ClassicalSignature"]
