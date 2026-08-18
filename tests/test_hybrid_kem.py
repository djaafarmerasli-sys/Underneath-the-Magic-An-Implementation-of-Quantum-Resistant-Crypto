"""Tests for pqcrypto.hybrid.key_exchange (X25519 + ML-KEM hybrid KEM).

Run with:   pytest tests/test_hybrid_kem.py
Requires:   kyber-py and cryptography installed.

The hybrid construction's whole point is that BOTH the classical and the
post-quantum component must genuinely contribute to the final session key --
these tests verify that by tampering with one component at a time and
confirming the derived key changes, rather than trusting the implementation's
internal wiring.
"""

from __future__ import annotations

import dataclasses

import pytest

pytest.importorskip("kyber_py", reason="kyber-py is required for hybrid KEM tests")

from pqcrypto.hybrid.key_exchange import (
    FORMAT_VERSION,
    HybridCiphertext,
    HybridKeyExchange,
    HybridKeyExchangeError,
    HybridPublicKey,
    HybridSecretKey,
)

SESSION_KEY_LENGTH = 32  # AES-256


@pytest.fixture
def alice() -> HybridKeyExchange:
    return HybridKeyExchange()


@pytest.fixture
def bob() -> HybridKeyExchange:
    return HybridKeyExchange()


@pytest.fixture
def bob_identity(bob: HybridKeyExchange):
    return bob.generate_keypair()


# --------------------------------------------------------------- happy path ---

def test_both_parties_derive_same_session_key(alice, bob, bob_identity):
    bob_public, bob_secret = bob_identity
    ciphertext, alice_key = alice.initiate(bob_public)
    bob_key = bob.respond(bob_secret, ciphertext)
    assert alice_key == bob_key


def test_session_key_has_aes_256_length(alice, bob_identity):
    bob_public, _ = bob_identity
    _, alice_key = alice.initiate(bob_public)
    assert len(alice_key) == SESSION_KEY_LENGTH


def test_different_handshakes_produce_independent_session_keys(alice, bob, bob_identity):
    """Two initiations to the SAME recipient key must not collide -- each
    side generates fresh ephemeral/encapsulation randomness."""
    bob_public, _ = bob_identity
    _, key_a = alice.initiate(bob_public)
    _, key_b = alice.initiate(bob_public)
    assert key_a != key_b


# --------------------------------------------------- component contribution ---

def test_tampering_pq_ciphertext_changes_derived_key(alice, bob, bob_identity):
    """ML-KEM's implicit rejection means a tampered ciphertext does not raise
    -- it silently yields a different shared secret, so the derived session
    key must differ too."""
    bob_public, bob_secret = bob_identity
    ciphertext, alice_key = alice.initiate(bob_public)

    tampered_pq = bytearray(ciphertext.pq_ciphertext)
    tampered_pq[0] ^= 0xFF
    tampered_ciphertext = dataclasses.replace(ciphertext, pq_ciphertext=bytes(tampered_pq))

    bob_key = bob.respond(bob_secret, tampered_ciphertext)
    assert bob_key != alice_key


def test_tampering_classical_ciphertext_changes_derived_key(alice, bob, bob_identity):
    """Tampering the sender's ephemeral X25519 public key changes the DH
    output, so the derived session key must differ too."""
    bob_public, bob_secret = bob_identity
    ciphertext, alice_key = alice.initiate(bob_public)

    tampered_classical = bytearray(ciphertext.classical_ciphertext)
    tampered_classical[0] ^= 0xFF
    tampered_ciphertext = dataclasses.replace(
        ciphertext, classical_ciphertext=bytes(tampered_classical)
    )

    bob_key = bob.respond(bob_secret, tampered_ciphertext)
    assert bob_key != alice_key


def test_wrong_secret_key_fails_to_reproduce_key(alice, bob, bob_identity):
    bob_public, _ = bob_identity
    ciphertext, alice_key = alice.initiate(bob_public)

    wrong_public, wrong_secret = bob.generate_keypair()
    assert wrong_public != bob_public  # sanity: genuinely a different identity

    responder_key = bob.respond(wrong_secret, ciphertext)
    assert responder_key != alice_key


# ------------------------------------------------------------ handshake data ---

def test_incomplete_handshake_rejected_wrong_type(alice, bob, bob_identity):
    bob_public, bob_secret = bob_identity
    with pytest.raises(TypeError):
        alice.initiate("not-a-hybrid-public-key")
    with pytest.raises(TypeError):
        bob.respond("not-a-hybrid-secret-key", None)


def test_algorithm_identifier_mismatch_rejected(alice, bob, bob_identity):
    bob_public, bob_secret = bob_identity
    ciphertext, _ = alice.initiate(bob_public)
    wrong_algorithm = dataclasses.replace(ciphertext, classical_algorithm="X448")
    with pytest.raises(HybridKeyExchangeError):
        bob.respond(bob_secret, wrong_algorithm)


def test_ml_kem_security_level_mismatch_rejected(bob_identity):
    bob_public, bob_secret = bob_identity
    alice_at_1024 = HybridKeyExchange(ml_kem_security_level=1024)
    # bob_public was generated at the default 768 level -- initiating against
    # it with a mismatched-level instance is a caller bug, but respond() must
    # still reject the resulting mismatched ciphertext rather than silently
    # deriving a bogus key.
    bob_at_768 = HybridKeyExchange(ml_kem_security_level=768)
    bob_public_1024, bob_secret_1024 = alice_at_1024.generate_keypair()
    ciphertext, _ = alice_at_1024.initiate(bob_public_1024)
    with pytest.raises(HybridKeyExchangeError):
        bob_at_768.respond(bob_secret_1024, ciphertext)


def test_unsupported_format_version_rejected(alice, bob, bob_identity):
    bob_public, bob_secret = bob_identity
    ciphertext, _ = alice.initiate(bob_public)
    wrong_version = dataclasses.replace(ciphertext, version=FORMAT_VERSION + 1)
    with pytest.raises(HybridKeyExchangeError):
        bob.respond(bob_secret, wrong_version)


def test_malformed_pq_ciphertext_length_rejected(alice, bob, bob_identity):
    bob_public, bob_secret = bob_identity
    ciphertext, _ = alice.initiate(bob_public)
    truncated = dataclasses.replace(ciphertext, pq_ciphertext=ciphertext.pq_ciphertext[:10])
    with pytest.raises(HybridKeyExchangeError):
        bob.respond(bob_secret, truncated)


def test_initiate_rejects_malformed_public_key_material(alice):
    bogus_public_key = HybridPublicKey(classical_public_key=b"\x00" * 4, pq_public_key=b"\x00" * 4)
    with pytest.raises(HybridKeyExchangeError):
        alice.initiate(bogus_public_key)


# -------------------------------------------------------------------- misc ---

def test_generate_keypair_returns_distinct_keys(alice):
    public_a, secret_a = alice.generate_keypair()
    public_b, secret_b = alice.generate_keypair()
    assert public_a.classical_public_key != public_b.classical_public_key
    assert public_a.pq_public_key != public_b.pq_public_key
    assert secret_a.classical_secret_key != secret_b.classical_secret_key
    assert secret_a.pq_secret_key != secret_b.pq_secret_key


def test_no_secret_material_leaked_in_errors(alice, bob, bob_identity):
    bob_public, bob_secret = bob_identity
    try:
        alice.initiate("not-a-hybrid-public-key")
    except TypeError as exc:
        assert bob_secret.classical_secret_key.hex() not in str(exc)
        assert bob_secret.pq_secret_key.hex() not in str(exc)
