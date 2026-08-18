"""Tests for pqcrypto.kem.ml_kem (the ML-KEM / Kyber wrapper).

Run with:   pytest tests/test_ml_kem.py
Requires:   kyber-py installed (the wrapper's backend).

A KEM has two properties worth pinning down with tests:
  1. Correctness -- both parties derive the SAME shared secret.
  2. Safe failure -- a tampered ciphertext degrades quietly (implicit
     rejection) instead of raising or leaking information.
Each test runs once per FIPS 203 security level (512 / 768 / 1024).
"""

from __future__ import annotations

import pytest

# The wrapper's backend is kyber-py. If it isn't installed, skip this whole
# module cleanly rather than erroring out during collection.
pytest.importorskip("kyber_py", reason="kyber-py is required for the ML-KEM tests")

from pqcrypto.kem.ml_kem import MLKEM, SHARED_SECRET_SIZE

# The three standardized parameter sets; every fixture-based test runs on each.
SECURITY_LEVELS = [512, 768, 1024]


@pytest.fixture(params=SECURITY_LEVELS)
def kem(request):
    """An MLKEM instance, yielded once per security level."""
    return MLKEM(request.param)


# --------------------------------------------------------------- happy path ---

def test_roundtrip_yields_matching_secret(kem):
    """Sender and recipient must arrive at the identical shared secret."""
    public_key, secret_key = kem.generate_keypair()
    ciphertext, secret_sender = kem.encapsulate(public_key)
    secret_recipient = kem.decapsulate(secret_key, ciphertext)
    assert secret_sender == secret_recipient


def test_shared_secret_is_32_bytes(kem):
    """Every ML-KEM level yields a 256-bit (32-byte) shared secret."""
    public_key, _ = kem.generate_keypair()
    _, shared_secret = kem.encapsulate(public_key)
    assert len(shared_secret) == SHARED_SECRET_SIZE == 32


def test_component_sizes_match_advertised(kem):
    """Real artifacts match the sizes the wrapper advertises via its properties."""
    public_key, secret_key = kem.generate_keypair()
    ciphertext, _ = kem.encapsulate(public_key)
    assert len(public_key) == kem.public_key_size
    assert len(secret_key) == kem.secret_key_size
    assert len(ciphertext) == kem.ciphertext_size


# ----------------------------------------------------------- randomization ---

def test_keypairs_are_unique(kem):
    """Two keygen calls must not collide -- keys are freshly random each time."""
    pk1, sk1 = kem.generate_keypair()
    pk2, sk2 = kem.generate_keypair()
    assert pk1 != pk2
    assert sk1 != sk2


def test_encapsulations_are_unique(kem):
    """Encapsulating twice to one key gives a different ct AND a different secret."""
    public_key, _ = kem.generate_keypair()
    ct1, s1 = kem.encapsulate(public_key)
    ct2, s2 = kem.encapsulate(public_key)
    assert ct1 != ct2
    assert s1 != s2


# ------------------------------------------------ implicit rejection (IND-CCA2) ---

def test_tampered_ciphertext_does_not_raise_and_diverges(kem):
    """A flipped ciphertext byte must NOT raise; it yields a different secret.

    This is ML-KEM's implicit rejection: decapsulation always returns *some*
    32-byte value, so an attacker can't turn 'bad ciphertext' into a visible
    exception or obvious timing tell. The two sides simply fail to agree later.
    """
    public_key, secret_key = kem.generate_keypair()
    ciphertext, secret_sender = kem.encapsulate(public_key)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF  # flip the first byte
    secret_from_tampered = kem.decapsulate(secret_key, bytes(tampered))

    assert secret_from_tampered != secret_sender
    assert len(secret_from_tampered) == SHARED_SECRET_SIZE


def test_wrong_secret_key_diverges(kem):
    """Decapsulating with an unrelated secret key yields a different secret."""
    public_key, _ = kem.generate_keypair()
    _, wrong_secret_key = kem.generate_keypair()
    ciphertext, secret_sender = kem.encapsulate(public_key)

    recovered = kem.decapsulate(wrong_secret_key, ciphertext)
    assert recovered != secret_sender


# ------------------------------------------------------- malformed input guards ---
# Implicit rejection (above) covers same-length-but-tampered ciphertexts. Wrong
# *type* or wrong *length* input is a different failure mode -- it's rejected
# up front with a clear error instead of reaching the backend at all.

def test_wrong_key_type_rejected(kem):
    """A non-bytes object where a key/ciphertext is expected raises TypeError."""
    public_key, secret_key = kem.generate_keypair()
    with pytest.raises(TypeError):
        kem.encapsulate("not-bytes")
    with pytest.raises(TypeError):
        kem.decapsulate("not-bytes", b"\x00" * kem.ciphertext_size)
    with pytest.raises(TypeError):
        kem.decapsulate(secret_key, 12345)


def test_wrong_length_public_key_rejected(kem):
    """An under/oversized public key is rejected before it reaches the backend."""
    with pytest.raises(ValueError):
        kem.encapsulate(b"\x00" * 4)


def test_truncated_ciphertext_handled_safely(kem):
    """A ciphertext shorter than expected is rejected with a clear error --
    not silently accepted, and not left to crash unpredictably inside the
    backend. This is distinct from implicit rejection: a truncated ciphertext
    is malformed input, not a same-length tampered one."""
    public_key, secret_key = kem.generate_keypair()
    ciphertext, _ = kem.encapsulate(public_key)
    truncated = ciphertext[: len(ciphertext) // 2]
    with pytest.raises(ValueError):
        kem.decapsulate(secret_key, truncated)


# ---------------------------------------------------------------- API guards ---

def test_default_security_level_is_768():
    assert MLKEM().security_level == 768


@pytest.mark.parametrize("bad_level", [0, 256, 511, 769, 1025, 2048, -768])
def test_invalid_security_level_rejected(bad_level):
    with pytest.raises(ValueError):
        MLKEM(bad_level)


def test_repr_mentions_level():
    assert repr(MLKEM(1024)) == "MLKEM(security_level=1024)"
