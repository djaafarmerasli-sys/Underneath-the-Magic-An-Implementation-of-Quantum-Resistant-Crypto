"""
ml_dsa.py -- ML-DSA digital signature wrapper
================================================

WHAT IS ML-DSA?
-----------------
ML-DSA (Module-Lattice-Based Digital Signature Algorithm) was standardized by
NIST as FIPS 204 in 2024. It was derived from CRYSTALS-Dilithium, the
finalist algorithm from NIST's post-quantum cryptography competition; you may
still see "Dilithium" in other libraries and papers, but this project uses
the standardized "ML-DSA" name throughout.

WHAT IS A DIGITAL SIGNATURE?
-------------------------------
A digital signature lets the holder of a *secret key* prove authorship of a
message to anyone holding the matching *public key*, without revealing the
secret key. Three operations:

    generate_keypair()               -> (public_key, secret_key)
    sign(message, secret_key)        -> signature
    verify(message, signature, public_key) -> bool

Unlike ML-KEM, this is NOT about agreeing on a secret -- it's about
authenticity and integrity: anyone with the public key can confirm a message
came from the secret-key holder and was not altered, but nobody without the
secret key can forge a valid signature for a new message.

WHY IS IT QUANTUM-RESISTANT?
-------------------------------
Like ML-KEM, ML-DSA's security rests on the Module Learning-With-Errors
problem over structured lattices, plus a "Fiat-Shamir with aborts" signing
construction built on top of it. This is unrelated to the discrete-log/
factoring assumptions that Shor's algorithm breaks, so a large quantum
computer is not known to threaten it. As with ML-KEM, "believed resistant to
quantum attack" describes the current state of cryptanalysis, not a proof.

PARAMETER SETS
-----------------
Three parameter sets trade signature/key size against security strength (all
sizes in bytes, per FIPS 204):

    level  NIST cat.  ~symmetric equiv.  public key  secret key  signature
    44       2        AES-128              1312       2560        2420
    65       3        AES-192              1952       4032        3309
    87       5        AES-256              2592       4896        4627

Level 65 is the default -- the balance NIST recommends for most uses.
Security levels are never silently substituted: an unsupported level raises
immediately rather than falling back to a weaker one.

IMPLEMENTATION NOTE & SECURITY DISCLAIMER
--------------------------------------------
We do NOT reimplement the lattice math or the signing/verification protocol
here -- you must never roll your own crypto. This module wraps `dilithium-py`,
a pure-Python implementation of FIPS 204 (from the same author and following
the same conventions as `kyber-py`), behind a small, stable interface: the
rest of this project depends only on the `MLDSA` class below, never on
dilithium-py's function names directly.

`dilithium-py`, like `kyber-py`, is an EDUCATIONAL implementation written for
clarity rather than production deployment. It makes no constant-time or
side-channel-resistance guarantees and has not been independently
security-audited. This project is itself an educational/research artifact for
the same reason -- see docs/security_analysis.md.
"""

from __future__ import annotations

# dilithium-py ships one ready-made object per FIPS 204 parameter set, each
# exposing .keygen(), .sign(sk, msg), and .verify(pk, msg, sig).
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

# One row per security level: the algorithm object plus the exact byte sizes
# FIPS 204 guarantees (see the table in the module docstring for the source).
_PARAMETER_SETS = {
    44: {"alg": ML_DSA_44, "public_key": 1312, "secret_key": 2560, "signature": 2420},
    65: {"alg": ML_DSA_65, "public_key": 1952, "secret_key": 4032, "signature": 3309},
    87: {"alg": ML_DSA_87, "public_key": 2592, "secret_key": 4896, "signature": 4627},
}


class MLDSAError(ValueError):
    """Raised for invalid MLDSA configuration or malformed key material.

    Subclasses ValueError so ``except ValueError`` keeps working for callers
    that don't need to distinguish this from other validation errors.
    """


class MLDSA:
    """A thin, well-documented wrapper around one ML-DSA parameter set.

    Instantiate once with a security level, then reuse the object for as many
    key pairs / signatures as you like -- it holds no per-key state.

    Example
    -------
    >>> dsa = MLDSA(65)
    >>> public_key, secret_key = dsa.generate_keypair()
    >>> signature = dsa.sign(b"hello", secret_key)
    >>> dsa.verify(b"hello", signature, public_key)
    True
    """

    def __init__(self, security_level: int = 65) -> None:
        if security_level not in _PARAMETER_SETS:
            raise MLDSAError(
                f"security_level must be one of {sorted(_PARAMETER_SETS)}; "
                f"got {security_level!r}"
            )

        params = _PARAMETER_SETS[security_level]
        self.security_level = security_level
        self._alg = params["alg"]
        self._public_key_size = params["public_key"]
        self._secret_key_size = params["secret_key"]
        self._signature_size = params["signature"]

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Create a fresh (public_key, secret_key) pair."""
        public_key, secret_key = self._alg.keygen()
        return public_key, secret_key

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign `message` with `secret_key`, returning the signature.

        Raises
        ------
        TypeError
            If `message` or `secret_key` is not bytes/bytearray.
        MLDSAError
            If `secret_key` is not exactly `secret_key_size` bytes for this
            security level.

        Note: dilithium-py's own argument order is `sign(secret_key, message)`;
        we accept `(message, secret_key)` here to match this project's public
        API (see the master file spec), and reorder internally.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(f"message must be bytes, got {type(message).__name__}")
        self._validate_key("secret_key", secret_key, self._secret_key_size)
        return self._alg.sign(bytes(secret_key), bytes(message))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify `signature` over `message` under `public_key`.

        Returns True only for a valid signature; False for every other case
        (wrong message, wrong/tampered signature, wrong public key). This
        method is a total function over well-typed input -- it never raises
        for adversarial-but-correctly-typed `signature` bytes, so callers can
        treat its return value as the complete answer without needing a
        try/except around a security check.

        Raises
        ------
        TypeError
            If `message`, `signature`, or `public_key` is not bytes/bytearray.
        MLDSAError
            If `public_key` is not exactly `public_key_size` bytes for this
            security level -- a configuration error, not an untrusted-input one.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(f"message must be bytes, got {type(message).__name__}")
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError(f"signature must be bytes, got {type(signature).__name__}")
        self._validate_key("public_key", public_key, self._public_key_size)

        try:
            return bool(self._alg.verify(bytes(public_key), bytes(message), bytes(signature)))
        except Exception:
            # A malformed (wrong-length/malformed-content) signature must be
            # treated as "does not verify", not surfaced as a crash -- verify()
            # promises a safe boolean for any well-typed input. We deliberately
            # catch broadly here because the backend's failure modes on
            # malformed signature bytes aren't part of its documented,
            # stable contract.
            return False

    # ------------------------------------------------------------ metadata ---
    @property
    def public_key_size(self) -> int:
        """Size in bytes of a public key for this security level."""
        return self._public_key_size

    @property
    def secret_key_size(self) -> int:
        """Size in bytes of a secret key for this security level."""
        return self._secret_key_size

    @property
    def signature_size(self) -> int:
        """Size in bytes of a signature for this security level."""
        return self._signature_size

    # -------------------------------------------------------------- guards ---
    @staticmethod
    def _validate_key(name: str, value: object, expected_size: int) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
        if len(value) != expected_size:
            raise MLDSAError(
                f"{name} has invalid length: expected {expected_size} bytes, "
                f"got {len(value)}"
            )

    def __repr__(self) -> str:
        return f"MLDSA(security_level={self.security_level})"
