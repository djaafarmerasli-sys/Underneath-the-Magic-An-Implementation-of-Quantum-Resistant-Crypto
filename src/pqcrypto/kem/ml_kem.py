"""
ml_kem.py -- ML-KEM Key Encapsulation Mechanism wrapper
=========================================================

WHAT PROBLEM DOES THIS SOLVE?
-----------------------------
Two parties who have never met need to agree on a shared secret key over a
public channel that an eavesdropper can read. Classically we do this with RSA
key transport or (elliptic-curve) Diffie-Hellman. Both rest on math problems
-- integer factorization and discrete logarithms -- that a large quantum
computer running *Shor's algorithm* could solve efficiently, breaking them.
ML-KEM is the NIST-standardized replacement believed to resist quantum
attacks.

WHAT IS ML-KEM?
----------------
ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) was standardized by
NIST as FIPS 203 in 2024. It was derived from CRYSTALS-Kyber, the finalist
algorithm selected in NIST's post-quantum cryptography competition; you may
still see the older name "Kyber" in other libraries and papers, but this
project uses the standardized "ML-KEM" name throughout.

WHAT IS A "KEM"?
----------------
A Key Encapsulation Mechanism is NOT general-purpose encryption -- you never
feed it your message. It does exactly one job: let a sender create a fresh
random *shared secret* and a *ciphertext* that carries that secret to the
holder of a private key. The three operations are:

    generate_keypair()                    -> (public_key, secret_key)
    encapsulate(public_key)               -> (ciphertext, shared_secret)  # SENDER
    decapsulate(secret_key, ciphertext)   -> shared_secret                # RECIPIENT

Both sides end up holding the SAME 32-byte shared secret. That secret is then
run through a KDF (see pqcrypto.hybrid.kdf, once implemented) and the result
used as an AES key to actually encrypt data. Splitting "agree on a key"
(asymmetric, slow, quantum-resistant) from "encrypt the bytes" (symmetric AES,
fast) is the standard hybrid pattern every real protocol uses. ML-KEM must
never be used to encrypt bulk data directly.

WHY IS IT QUANTUM-RESISTANT?
----------------------------
ML-KEM's security rests on the *Module Learning-With-Errors* (Module-LWE)
problem over structured lattices: given many noisy linear equations, recover
the hidden secret. No efficient quantum (or classical) algorithm is known for
this problem. Because it is a completely different hardness assumption than
factoring or discrete-log, Shor's algorithm does not apply to it. "Believed
resistant to quantum attack" is a statement about the current state of
cryptanalysis, not a mathematical proof of unbreakability.

STANDARD & PARAMETER SETS
-------------------------
Three parameter sets trade security strength against key/ciphertext size (all
sizes in bytes, per FIPS 203):

    level  NIST cat.  ~symmetric equiv.  public key  secret key  ciphertext  secret
    512      1        AES-128              800        1632         768         32
    768      3        AES-192             1184        2400        1088         32
    1024     5        AES-256             1568        3168        1568         32

Level 768 is the default -- the balance NIST recommends for most uses, and
what protocols like TLS hybrid key exchange adopted. Security levels are never
silently substituted: requesting an unsupported level raises immediately.

IMPLEMENTATION NOTE & SECURITY DISCLAIMER
------------------------------------------
We do NOT reimplement the lattice math here -- you must never roll your own
crypto. This module is a thin wrapper around `kyber-py`, a pure-Python
implementation of FIPS 203, behind a small, stable interface: the rest of this
project depends only on the `MLKEM` class below, never on kyber-py's function
names directly, so swapping backends later means editing only this file.

`kyber-py` is an EDUCATIONAL implementation. It is written for clarity, not for
production deployment: it makes no constant-time or side-channel-resistance
guarantees, has not been independently security-audited, and should not be
treated as production-grade cryptographic software. This project is itself an
educational/research artifact for the same reason -- see docs/security_analysis.md.
"""

from __future__ import annotations

# kyber-py ships one ready-made object per FIPS 203 parameter set. Each object
# exposes .keygen(), .encaps(ek) and .decaps(dk, ct). We import all three so a
# caller can pick a security level at runtime.
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

# One row per security level: the algorithm object plus the exact byte sizes
# FIPS 203 guarantees (see the table in the module docstring for the source).
# Caching the sizes lets callers (e.g. the benchmarks) report key/ciphertext
# sizes without generating a key first, and lets us validate input lengths
# before ever handing them to the backend.
_PARAMETER_SETS = {
    512:  {"alg": ML_KEM_512,  "public_key": 800,  "secret_key": 1632, "ciphertext": 768},
    768:  {"alg": ML_KEM_768,  "public_key": 1184, "secret_key": 2400, "ciphertext": 1088},
    1024: {"alg": ML_KEM_1024, "public_key": 1568, "secret_key": 3168, "ciphertext": 1568},
}

# Every ML-KEM parameter set produces the same 32-byte (256-bit) shared secret.
SHARED_SECRET_SIZE = 32


class MLKEMError(ValueError):
    """Raised for invalid MLKEM configuration or malformed key/ciphertext material.

    Subclasses ValueError so ``except ValueError`` (or ``pytest.raises(ValueError)``)
    keeps working for callers that don't need to distinguish this from other
    validation errors, while still letting callers that DO care catch it by name.
    """


class MLKEM:
    """A thin, well-documented wrapper around one ML-KEM parameter set.

    Instantiate once with a security level, then reuse the object for as many
    key pairs / encapsulations as you like -- it holds no per-key state.

    Example
    -------
    >>> kem = MLKEM(768)
    >>> public_key, secret_key = kem.generate_keypair()
    >>> ciphertext, secret_sender = kem.encapsulate(public_key)
    >>> secret_recipient = kem.decapsulate(secret_key, ciphertext)
    >>> secret_sender == secret_recipient
    True
    """

    def __init__(self, security_level: int = 768) -> None:
        # Reject anything that isn't one of the three standardized sets.
        # Silently downgrading to a weaker level would be a security footgun,
        # so we fail loudly instead of guessing what the caller meant.
        if security_level not in _PARAMETER_SETS:
            raise MLKEMError(
                f"security_level must be one of {sorted(_PARAMETER_SETS)}; "
                f"got {security_level!r}"
            )

        params = _PARAMETER_SETS[security_level]
        self.security_level = security_level
        # The underlying kyber-py object that performs the real lattice math.
        self._alg = params["alg"]
        # Expected byte sizes for this level, used by the size properties below
        # AND to validate input material before it ever reaches the backend.
        self._public_key_size = params["public_key"]
        self._secret_key_size = params["secret_key"]
        self._ciphertext_size = params["ciphertext"]

    # ----------------------------------------------------------------- keys ---
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Create a fresh (public_key, secret_key) pair.

        FIPS 203 calls these the *encapsulation key* (public -- hand it out so
        anyone can send you a secret) and the *decapsulation key* (secret --
        keep it private; only it can recover secrets sent to you).

        kyber-py returns them as (ek, dk) == (public, secret), which is exactly
        the order we return, so no re-shuffling is needed here.
        """
        public_key, secret_key = self._alg.keygen()
        return public_key, secret_key

    # --------------------------------------------------------------- sender ---
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """SENDER side: given the recipient's public key, mint a shared secret.

        This single call does two things at once:
          * generates a brand-new random 32-byte shared secret, and
          * seals it into a `ciphertext` that only the matching secret key opens.

        You transmit `ciphertext` over the public wire and keep `shared_secret`
        as your symmetric key. The secret is created HERE, locally -- it never
        travels across the network in the clear; only the ciphertext does.

        Raises
        ------
        TypeError
            If `public_key` is not bytes/bytearray.
        MLKEMError
            If `public_key` is not exactly `public_key_size` bytes for this
            security level -- a malformed or wrong-level key, caught before it
            can reach (and potentially misbehave inside) the backend.

        Ordering note: kyber-py hands back (shared_secret, ciphertext). We
        deliberately return (ciphertext, shared_secret) so the tuple reads
        "the thing you send, then the thing you keep".
        """
        self._validate_bytes("public_key", public_key, self._public_key_size)
        shared_secret, ciphertext = self._alg.encaps(public_key)
        return ciphertext, shared_secret

    # ------------------------------------------------------------ recipient ---
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """RECIPIENT side: recover the same shared secret from the ciphertext.

        When both sides are honest, this returns byte-for-byte the same
        `shared_secret` the sender produced in `encapsulate`.

        Raises
        ------
        TypeError
            If `secret_key` or `ciphertext` is not bytes/bytearray.
        MLKEMError
            If `secret_key` or `ciphertext` has the wrong length for this
            security level (e.g. truncated or corrupted framing) -- rejected
            with a clear error rather than passed to the backend, which might
            otherwise fail unpredictably on malformed-length input.

        IMPORTANT -- *implicit rejection*: for a ciphertext that IS the right
        length but has been tampered with (bit-flipped, swapped for another
        valid ciphertext, etc.), ML-KEM is deliberately designed so
        decapsulation NEVER raises. Instead it deterministically returns a
        *different* pseudo-random secret (derived from a secret "rejection"
        value baked into the private key). Because a bad same-length
        ciphertext looks identical to a good one from the outside -- no
        exception, no timing tell -- an attacker cannot probe the private key
        with crafted ciphertexts. This is what makes the scheme IND-CCA2
        secure. The mismatch surfaces harmlessly downstream: the two sides'
        derived AES keys simply won't agree and authentication fails. We do
        NOT catch this case and turn it into an error, because doing so would
        undermine the implicit-rejection design -- callers must compare/rely
        on the derived key(s) via a KDF and MAC/AEAD, not on decapsulate()
        raising.
        """
        self._validate_bytes("secret_key", secret_key, self._secret_key_size)
        self._validate_bytes("ciphertext", ciphertext, self._ciphertext_size)
        return self._alg.decaps(secret_key, ciphertext)

    # ------------------------------------------------------------ metadata ---
    # These sizes are fixed by the parameter set, so we expose them without
    # generating a key. Handy for the benchmarking module's size comparisons.
    @property
    def public_key_size(self) -> int:
        """Size in bytes of a public (encapsulation) key for this level."""
        return self._public_key_size

    @property
    def secret_key_size(self) -> int:
        """Size in bytes of a secret (decapsulation) key for this level."""
        return self._secret_key_size

    @property
    def ciphertext_size(self) -> int:
        """Size in bytes of the KEM ciphertext for this level."""
        return self._ciphertext_size

    @property
    def shared_secret_size(self) -> int:
        """Size in bytes of the shared secret (32 for every ML-KEM level)."""
        return SHARED_SECRET_SIZE

    # -------------------------------------------------------------- guards ---
    @staticmethod
    def _validate_bytes(name: str, value: object, expected_size: int) -> None:
        """Shared input guard for every public/secret key and ciphertext.

        Centralizing this means every method rejects wrong types and wrong
        lengths the same way, with the same clear error messages, instead of
        letting each call site invent its own (or forget to check at all).
        """
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
        if len(value) != expected_size:
            raise MLKEMError(
                f"{name} has invalid length: expected {expected_size} bytes, "
                f"got {len(value)}"
            )

    def __repr__(self) -> str:
        return f"MLKEM(security_level={self.security_level})"
