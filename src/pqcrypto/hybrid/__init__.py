"""Hybrid classical + post-quantum cryptography for pqcrypto.

Combines classical and post-quantum primitives -- key exchange, digital
signatures, and a KDF for merging independent shared secrets -- for defense
during the transition period to post-quantum cryptography: the resulting
session key/signature stays secure as long as at least one of the two
underlying mechanisms remains unbroken. See pqcrypto.hybrid.kdf for the KDF
combiner and docs/security_analysis.md for the composition assumptions this
makes explicit rather than glosses over.
"""

from .key_exchange import HybridKeyExchange
from .signatures import HybridSigner

__all__ = ["HybridKeyExchange", "HybridSigner"]
