"""Tests for pqcrypto.signatures.ml_dsa (the ML-DSA wrapper).

Run with:   pytest tests/test_ml_dsa.py
Requires:   dilithium-py installed, AND pqcrypto.signatures.ml_dsa implemented.

HEADS UP: ml_dsa.py is still an empty stub. Until an MLDSA class exists there,
this whole module SKIPS cleanly (it does not error). It therefore doubles as
the *specification* for the interface ml_dsa.py should expose -- a signature-
side counterpart to the MLKEM wrapper:

    MLDSA(security_level)                          # 44 / 65 / 87  (default 65)
    .generate_keypair()                  -> (public_key, secret_key)
    .sign(message, secret_key)           -> signature
    .verify(message, signature, public_key) -> bool
    .public_key_size / .secret_key_size / .signature_size

Where ML-KEM lets two parties AGREE on a secret, ML-DSA (FIPS 204, historically
CRYSTALS-Dilithium) lets one party PROVE authorship: sign with the secret key,
and anyone with the public key can verify -- but nobody can forge a signature
or alter the message undetected.
"""

from __future__ import annotations

import pytest

# Backend for the (future) wrapper -- skip the module if it isn't installed...
pytest.importorskip("dilithium_py", reason="dilithium-py is required for the ML-DSA tests")

# ...and skip if the wrapper itself hasn't been written yet, so this file stays
# green (skipped, not failed) until ml_dsa.py grows an MLDSA class.
ml_dsa = pytest.importorskip(
    "pqcrypto.signatures.ml_dsa", reason="pqcrypto.signatures.ml_dsa is not importable"
)
if not hasattr(ml_dsa, "MLDSA"):
    pytest.skip(
        "pqcrypto.signatures.ml_dsa.MLDSA is not implemented yet",
        allow_module_level=True,
    )

MLDSA = ml_dsa.MLDSA

# The three FIPS 204 parameter sets; every fixture-based test runs on each.
SECURITY_LEVELS = [44, 65, 87]
MESSAGE = b"The quick brown fox jumps over the lazy dog."
# ~64 KiB, deterministic (no randomness needed) -- stands in for "large message".
LARGE_MESSAGE = bytes(range(256)) * 256


@pytest.fixture(params=SECURITY_LEVELS)
def dsa(request):
    """An MLDSA instance, yielded once per security level."""
    return MLDSA(request.param)


# --------------------------------------------------------------- happy path ---

def test_sign_then_verify_succeeds(dsa):
    """A signature made with the secret key verifies under the matching public key."""
    public_key, secret_key = dsa.generate_keypair()
    signature = dsa.sign(MESSAGE, secret_key)
    assert dsa.verify(MESSAGE, signature, public_key) is True


def test_empty_message_is_signable(dsa):
    """Signing/verifying the empty message must work (a common edge case)."""
    public_key, secret_key = dsa.generate_keypair()
    signature = dsa.sign(b"", secret_key)
    assert dsa.verify(b"", signature, public_key) is True


def test_large_message_is_signable(dsa):
    """ML-DSA signs the message's hash internally, so size shouldn't matter --
    but we verify that explicitly rather than assuming it."""
    public_key, secret_key = dsa.generate_keypair()
    signature = dsa.sign(LARGE_MESSAGE, secret_key)
    assert dsa.verify(LARGE_MESSAGE, signature, public_key) is True


def test_component_sizes_match_advertised(dsa):
    """Real artifacts match the sizes the wrapper advertises via its properties."""
    public_key, secret_key = dsa.generate_keypair()
    signature = dsa.sign(MESSAGE, secret_key)
    assert len(public_key) == dsa.public_key_size
    assert len(secret_key) == dsa.secret_key_size
    assert len(signature) == dsa.signature_size


# ------------------------------------------------------------- forgery guards ---

def test_verify_rejects_tampered_message(dsa):
    """Changing even one byte of the message must invalidate the signature."""
    public_key, secret_key = dsa.generate_keypair()
    signature = dsa.sign(MESSAGE, secret_key)
    assert dsa.verify(MESSAGE + b"!", signature, public_key) is False


def test_verify_rejects_tampered_signature(dsa):
    """A flipped signature byte must fail verification (no forgery)."""
    public_key, secret_key = dsa.generate_keypair()
    signature = bytearray(dsa.sign(MESSAGE, secret_key))
    signature[0] ^= 0xFF
    assert dsa.verify(MESSAGE, bytes(signature), public_key) is False


def test_verify_rejects_wrong_public_key(dsa):
    """A valid signature must not verify under an unrelated public key."""
    _, secret_key = dsa.generate_keypair()
    other_public_key, _ = dsa.generate_keypair()
    signature = dsa.sign(MESSAGE, secret_key)
    assert dsa.verify(MESSAGE, signature, other_public_key) is False


# ----------------------------------------------------------- randomization ---

def test_keypairs_are_unique(dsa):
    """Two keygen calls must not collide."""
    pk1, sk1 = dsa.generate_keypair()
    pk2, sk2 = dsa.generate_keypair()
    assert pk1 != pk2
    assert sk1 != sk2


def test_repeated_signing_both_verify(dsa):
    """Signing the same message twice must always verify both times.

    ML-DSA signing may or may not be randomized/hedged depending on the
    backend, so we deliberately do NOT assert the two signatures are equal
    (deterministic) or different (randomized) -- only that both are valid.
    """
    public_key, secret_key = dsa.generate_keypair()
    signature_a = dsa.sign(MESSAGE, secret_key)
    signature_b = dsa.sign(MESSAGE, secret_key)
    assert dsa.verify(MESSAGE, signature_a, public_key) is True
    assert dsa.verify(MESSAGE, signature_b, public_key) is True


# ---------------------------------------------------------------- API guards ---

def test_default_security_level_is_65():
    assert MLDSA().security_level == 65


@pytest.mark.parametrize("bad_level", [0, 43, 66, 88, 512, -65])
def test_invalid_security_level_rejected(bad_level):
    with pytest.raises(ValueError):
        MLDSA(bad_level)


def test_invalid_message_type_rejected(dsa):
    """A non-bytes message must be rejected rather than coerced or crashing deep
    inside the backend."""
    _, secret_key = dsa.generate_keypair()
    with pytest.raises(TypeError):
        dsa.sign("not-bytes", secret_key)


def test_repr_mentions_level():
    assert repr(MLDSA(87)) == "MLDSA(security_level=87)"
