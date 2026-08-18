"""
randomness.py -- cryptographically secure random bytes for pqcrypto
=====================================================================

Provides `random_bytes(length)` for the small set of project-level needs that
legitimately require application-level randomness -- e.g. a salt for a
passphrase-based key-derivation function, or a random key identifier.

ML-KEM and ML-DSA manage their OWN algorithm-specific randomness internally,
according to their respective FIPS specifications (FIPS 203 / FIPS 204). This
module is never used to seed those algorithms -- it exists only for the
project's own supporting code (see pqcrypto.keys.key_storage).

We use Python's `secrets` module, which draws from the OS's cryptographically
secure random source (os.urandom / CryptGenRandom on Windows). Never use
`random.random()`, `random.randbytes()`, or any other non-cryptographic PRNG
for security-relevant randomness -- the Mersenne Twister behind `random` is
fully predictable from a handful of its outputs and must never be used here.
"""

from __future__ import annotations

import secrets

# Generous ceiling on a single request. This project never needs anywhere
# near this much randomness at once; the limit exists purely to catch an
# obvious caller bug (e.g. accidentally passing a bit count instead of a byte
# count) rather than silently allocating an enormous buffer.
_MAX_REASONABLE_LENGTH = 2**20  # 1 MiB


class RandomnessError(ValueError):
    """Raised when an invalid length is requested from random_bytes()."""


def random_bytes(length: int) -> bytes:
    """Return `length` cryptographically secure random bytes.

    Raises
    ------
    TypeError
        If `length` is not an int (booleans are rejected too -- `True`/`False`
        are technically ints in Python, but accepting them here would almost
        certainly indicate a caller bug, not an intentional length of 1/0).
    RandomnessError
        If `length` is negative or exceeds the sanity ceiling.
    """
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be an int, got {type(length).__name__}")
    if length < 0:
        raise RandomnessError(f"length must be non-negative, got {length}")
    if length > _MAX_REASONABLE_LENGTH:
        raise RandomnessError(
            f"length {length} exceeds the maximum reasonable request "
            f"({_MAX_REASONABLE_LENGTH} bytes)"
        )
    return secrets.token_bytes(length)
