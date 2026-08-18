"""pqcrypto -- educational post-quantum and hybrid classical/PQC cryptography.

Implements the NIST-standardized ML-KEM (FIPS 203) key-encapsulation mechanism
and ML-DSA (FIPS 204) digital-signature algorithm, alongside classical
algorithms, hybrid key establishment, AES-256-GCM file encryption, and
supporting key-management utilities.

This is an educational/research project, not audited production cryptographic
infrastructure -- see docs/security_analysis.md for its security posture and
known limitations before relying on it for anything beyond learning and
experimentation.

Importing this top-level package does not import every submodule, and never
performs cryptographic operations as a side effect. Import the specific
subpackage you need instead:

    from pqcrypto.kem import MLKEM
    from pqcrypto.signatures import MLDSA
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
