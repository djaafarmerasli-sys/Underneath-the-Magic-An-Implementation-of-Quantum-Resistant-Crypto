"""Tests for pqcrypto.hybrid.signatures (ML-DSA + classical hybrid signing).

Run with:   pytest tests/test_hybrid_signatures.py
Requires:   dilithium-py and cryptography installed.

The default verification policy is ML-DSA valid AND classical valid -- a
signature that only satisfies one of the two algorithms must NOT verify.
These tests exercise that "both gates must pass" contract directly, plus the
structural checks (algorithm identifiers, format version) that let a
verifier reject a malformed/mismatched package before ever calling either
algorithm's verify().
"""

from __future__ import annotations

import dataclasses

import pytest

pytest.importorskip("dilithium_py", reason="dilithium-py is required for hybrid signature tests")

from pqcrypto.hybrid.signatures import (
    FORMAT_VERSION,
    HybridSignature,
    HybridSignaturePublicKeys,
    HybridSignatureSecretKeys,
    HybridSigner,
)

MESSAGE = b"transition-period hybrid signature"


@pytest.fixture
def signer() -> HybridSigner:
    """A default-configured (ML-DSA-65 + Ed25519) hybrid signer."""
    return HybridSigner()


@pytest.fixture
def identity(signer: HybridSigner):
    """One generated keypair set, ready to sign with."""
    public_keys, secret_keys = signer.generate_keypairs()
    return public_keys, secret_keys


# --------------------------------------------------------------- happy path ---

def test_both_signatures_verify_for_authentic_message(signer, identity):
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    assert signer.verify(MESSAGE, signature, public_keys) is True


def test_component_signatures_individually_valid(signer, identity):
    """Sanity check: the bundled signature is genuinely two independent,
    individually-valid signatures, not a single combined blob."""
    from pqcrypto.signatures.classical_signature import ClassicalSignature
    from pqcrypto.signatures.ml_dsa import MLDSA

    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)

    assert MLDSA(signature.ml_dsa_security_level).verify(
        MESSAGE, signature.ml_dsa_signature, public_keys.ml_dsa_public_key
    )
    assert ClassicalSignature().verify(
        MESSAGE, signature.classical_signature, public_keys.classical_public_key
    )


# ------------------------------------------------------------- forgery guards ---

def test_modified_message_fails(signer, identity):
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    assert signer.verify(MESSAGE + b"!", signature, public_keys) is False


def test_modified_ml_dsa_signature_fails(signer, identity):
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    tampered_pq = bytearray(signature.ml_dsa_signature)
    tampered_pq[0] ^= 0xFF
    tampered = dataclasses.replace(signature, ml_dsa_signature=bytes(tampered_pq))
    assert signer.verify(MESSAGE, tampered, public_keys) is False


def test_modified_classical_signature_fails(signer, identity):
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    tampered_classical = bytearray(signature.classical_signature)
    tampered_classical[0] ^= 0xFF
    tampered = dataclasses.replace(signature, classical_signature=bytes(tampered_classical))
    assert signer.verify(MESSAGE, tampered, public_keys) is False


def test_wrong_ml_dsa_public_key_fails(signer, identity):
    public_keys, secret_keys = identity
    other_public_keys, _ = signer.generate_keypairs()
    signature = signer.sign(MESSAGE, secret_keys)
    mismatched = dataclasses.replace(public_keys, ml_dsa_public_key=other_public_keys.ml_dsa_public_key)
    assert signer.verify(MESSAGE, signature, mismatched) is False


def test_wrong_classical_public_key_fails(signer, identity):
    public_keys, secret_keys = identity
    other_public_keys, _ = signer.generate_keypairs()
    signature = signer.sign(MESSAGE, secret_keys)
    mismatched = dataclasses.replace(
        public_keys, classical_public_key=other_public_keys.classical_public_key
    )
    assert signer.verify(MESSAGE, signature, mismatched) is False


def test_missing_signature_component_fails_safely(signer, identity):
    """An empty/absent signature component must be rejected, not raise or
    be treated as a wildcard match."""
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    missing_classical = dataclasses.replace(signature, classical_signature=b"")
    assert signer.verify(MESSAGE, missing_classical, public_keys) is False
    missing_pq = dataclasses.replace(signature, ml_dsa_signature=b"")
    assert signer.verify(MESSAGE, missing_pq, public_keys) is False


# --------------------------------------------------------- identifier guards ---

def test_wrong_algorithm_identifier_fails_safely(signer, identity):
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    wrong_algorithm = dataclasses.replace(signature, classical_algorithm="RSA-4096")
    assert signer.verify(MESSAGE, wrong_algorithm, public_keys) is False


def test_wrong_ml_dsa_security_level_identifier_fails_safely(signer, identity):
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    wrong_level = dataclasses.replace(signature, ml_dsa_security_level=87)
    assert signer.verify(MESSAGE, wrong_level, public_keys) is False


def test_wrong_version_fails_safely(signer, identity):
    public_keys, secret_keys = identity
    signature = signer.sign(MESSAGE, secret_keys)
    wrong_version = dataclasses.replace(signature, version=FORMAT_VERSION + 1)
    assert signer.verify(MESSAGE, wrong_version, public_keys) is False


# ------------------------------------------------------------- policy: AND ---

def test_verification_requires_both_signatures(signer, identity):
    """Neither component alone is sufficient: a signature valid under ONLY
    ML-DSA, or ONLY the classical algorithm, must not verify as a whole."""
    public_keys, secret_keys = identity
    valid = signer.sign(MESSAGE, secret_keys)

    only_classical_valid = dataclasses.replace(
        valid, ml_dsa_signature=bytes(bytearray(valid.ml_dsa_signature)[:-1] + b"\x00")
        if valid.ml_dsa_signature[-1] != 0
        else bytes(bytearray(valid.ml_dsa_signature)[:-1] + b"\x01")
    )
    assert signer.verify(MESSAGE, only_classical_valid, public_keys) is False

    only_pq_valid = dataclasses.replace(
        valid,
        classical_signature=bytes(bytearray(valid.classical_signature)[:-1] + b"\x00")
        if valid.classical_signature[-1] != 0
        else bytes(bytearray(valid.classical_signature)[:-1] + b"\x01"),
    )
    assert signer.verify(MESSAGE, only_pq_valid, public_keys) is False


# ------------------------------------------------------------- "serialization" ---

def test_reconstructed_signature_package_still_verifies(signer, identity):
    """Rebuilding a HybridSignature from the same field values (the shape a
    deserializer would produce) must verify identically to the original --
    the dataclass's fields are a complete, order-independent description of
    the signature package."""
    public_keys, secret_keys = identity
    original = signer.sign(MESSAGE, secret_keys)

    reconstructed = HybridSignature(
        ml_dsa_signature=original.ml_dsa_signature,
        classical_signature=original.classical_signature,
        ml_dsa_security_level=original.ml_dsa_security_level,
        classical_algorithm=original.classical_algorithm,
        version=original.version,
    )
    assert reconstructed == original
    assert signer.verify(MESSAGE, reconstructed, public_keys) is True


# -------------------------------------------------------------------- misc ---

def test_generate_keypairs_returns_distinct_keys_each_call(signer):
    public_a, secret_a = signer.generate_keypairs()
    public_b, secret_b = signer.generate_keypairs()
    assert public_a.ml_dsa_public_key != public_b.ml_dsa_public_key
    assert public_a.classical_public_key != public_b.classical_public_key
    assert secret_a.ml_dsa_secret_key != secret_b.ml_dsa_secret_key
    assert secret_a.classical_secret_key != secret_b.classical_secret_key


def test_wrong_type_rejected(signer, identity):
    public_keys, secret_keys = identity
    with pytest.raises(TypeError):
        signer.sign(MESSAGE, "not-a-secret-keys-object")
    with pytest.raises(TypeError):
        signer.verify("not-bytes", signer.sign(MESSAGE, secret_keys), public_keys)
    with pytest.raises(TypeError):
        signer.verify(MESSAGE, "not-a-signature", public_keys)
    with pytest.raises(TypeError):
        signer.verify(MESSAGE, signer.sign(MESSAGE, secret_keys), "not-public-keys")


def test_no_private_material_leaked_in_errors(signer, identity):
    """A TypeError raised for a bad argument must not echo secret key bytes
    into its message."""
    _, secret_keys = identity
    try:
        signer.sign(MESSAGE, "not-a-secret-keys-object")
    except TypeError as exc:
        message = str(exc)
        assert secret_keys.ml_dsa_secret_key.hex() not in message
        assert secret_keys.classical_secret_key.hex() not in message


def test_repr_mentions_configuration():
    signer = HybridSigner(44)
    text = repr(signer)
    assert "44" in text
    assert "Ed25519" in text
