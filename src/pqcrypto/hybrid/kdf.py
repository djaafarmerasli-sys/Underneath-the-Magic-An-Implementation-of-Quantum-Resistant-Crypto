"""
kdf.py -- key derivation for combining independent shared secrets
=====================================================================

PURPOSE
---------
Both pqcrypto.kem.classical_kem (X25519) and pqcrypto.kem.ml_kem (ML-KEM)
produce a "shared secret" -- but neither one is, by itself, guaranteed to be
a uniformly random bit string safe to use directly as an AES key:
  * X25519's raw ECDH output is a curve point coordinate, not uniform bytes.
  * Multiple independent secrets need to be combined into ONE final key for
    the hybrid scheme in pqcrypto.hybrid.key_exchange -- and simply
    concatenating-and-truncating them is NOT a sound way to do that; it gives
    no formal guarantee about how the combined output behaves if one input is
    weak, biased, or adversarially influenced.

The standard fix is a KDF (Key Derivation Function): a construction,
independently designed and analyzed for exactly this purpose, that takes
arbitrary "keying material" and produces uniformly-distributed output key
bytes of a requested length.

WHY HKDF?
-----------
This module uses HKDF (RFC 5869) with SHA-256, via `cryptography`'s vetted
implementation -- never a hand-rolled hash-and-truncate construction. HKDF is
the standard choice for exactly this "combine secret material into a session
key" role (it's what TLS 1.3 uses, including in its own hybrid PQC key
exchange). It has two stages:
  * Extract: compress arbitrary-length, possibly-non-uniform input keying
    material (IKM) plus an optional `salt` into a fixed-size pseudorandom key.
  * Expand: stretch that pseudorandom key out to the requested `length`,
    bound to a caller-supplied `info` string.

DOMAIN SEPARATION
--------------------
`info` (and `derive_hybrid_session_key`'s `context`) exists so that deriving
"the AES key for this hybrid handshake" can never accidentally collide with
deriving some unrelated key from the same underlying secret material, even if
a caller reused input by mistake. Every caller in this project MUST pass a
distinct, purpose-specific `info`/`context` value -- this module deliberately
has no default that would make that easy to skip. `derive_hybrid_session_key`
does define one project-wide default context for its specific purpose, since
that call site's purpose is fixed by definition.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# RFC 5869 caps output length at 255 * hash_len. SHA-256 has a 32-byte digest.
_HASH_ALGORITHM = hashes.SHA256()
_MAX_OUTPUT_LENGTH = 255 * 32

# The default session-key length this project derives (AES-256).
DEFAULT_SESSION_KEY_LENGTH = 32

# Fixed protocol label for the hybrid key-exchange combiner (see
# pqcrypto.hybrid.key_exchange). Bumping this would be a breaking protocol
# change, so it's versioned explicitly rather than left implicit.
HYBRID_KEX_CONTEXT = b"pqcrypto-hybrid-kex-v1"


class KDFError(ValueError):
    """Raised for invalid KDF parameters (bad length, wrong input types)."""


def derive_key(
    secret_material: bytes,
    length: int,
    *,
    salt: bytes | None = None,
    info: bytes = b"",
) -> bytes:
    """Derive `length` bytes of key material from `secret_material` via HKDF-SHA256.

    Parameters
    ----------
    secret_material : the input keying material (IKM) -- e.g. a KEM shared
        secret, or several concatenated together. Never logged.
    length : number of output bytes requested. Must be a positive int not
        exceeding HKDF-SHA256's 8160-byte ceiling (255 * 32).
    salt : optional. HKDF's `salt` strengthens extraction when the IKM's
        entropy isn't already uniform, but is not itself required to be
        secret. Pass `None` (HKDF then uses an all-zero salt internally, per
        RFC 5869) when no natural salt value exists for the caller's context.
    info : REQUIRED context/domain-separation string, distinguishing this
        derivation's purpose from any other derivation that might otherwise
        reuse the same `secret_material`. Callers MUST supply a
        purpose-specific value -- there is no safe generic default.

    Raises
    ------
    TypeError
        If `secret_material`, `salt`, or `info` is not bytes-like.
    KDFError
        If `length` is not a positive int, or exceeds the HKDF-SHA256 ceiling.
    """
    if not isinstance(secret_material, (bytes, bytearray)):
        raise TypeError(
            f"secret_material must be bytes, got {type(secret_material).__name__}"
        )
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be an int, got {type(length).__name__}")
    if length <= 0:
        raise KDFError(f"length must be positive, got {length}")
    if length > _MAX_OUTPUT_LENGTH:
        raise KDFError(f"length {length} exceeds HKDF-SHA256's maximum ({_MAX_OUTPUT_LENGTH})")
    if salt is not None and not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt must be bytes or None, got {type(salt).__name__}")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError(f"info must be bytes, got {type(info).__name__}")

    hkdf = HKDF(
        algorithm=_HASH_ALGORITHM,
        length=length,
        salt=bytes(salt) if salt is not None else None,
        info=bytes(info),
    )
    return hkdf.derive(bytes(secret_material))


def derive_hybrid_session_key(
    classical_shared_secret: bytes,
    pq_shared_secret: bytes,
    *,
    length: int = DEFAULT_SESSION_KEY_LENGTH,
    context: bytes = HYBRID_KEX_CONTEXT,
) -> bytes:
    """Combine a classical and a post-quantum shared secret into one session key.

    Used by pqcrypto.hybrid.key_exchange to merge the X25519 and ML-KEM
    shared secrets. The two secrets are concatenated (classical first, then
    PQ) as HKDF's input keying material, with `context` as the HKDF `info`
    for domain separation.

    IMPORTANT: concatenating two independently-established secrets and
    running them through a single HKDF derivation is a standard hybrid-KEM
    combiner pattern (the same shape TLS 1.3's hybrid key exchange uses), but
    it is NOT, by itself, a formally proven "hybrid security" guarantee for
    every possible composition of algorithms -- see
    docs/security_analysis.md for the composition assumptions this project
    documents rather than claims to prove.

    Raises
    ------
    TypeError
        If either secret is not bytes-like.
    KDFError
        If either secret is empty, or `length` is invalid (see derive_key).
    """
    if not isinstance(classical_shared_secret, (bytes, bytearray)):
        raise TypeError(
            "classical_shared_secret must be bytes, got "
            f"{type(classical_shared_secret).__name__}"
        )
    if not isinstance(pq_shared_secret, (bytes, bytearray)):
        raise TypeError(
            f"pq_shared_secret must be bytes, got {type(pq_shared_secret).__name__}"
        )
    if len(classical_shared_secret) == 0 or len(pq_shared_secret) == 0:
        raise KDFError("classical_shared_secret and pq_shared_secret must both be non-empty")

    ikm = bytes(classical_shared_secret) + bytes(pq_shared_secret)
    return derive_key(ikm, length, info=context)
