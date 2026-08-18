"""End-to-end integration tests for the complete pqcrypto pipeline.

Run with:   pytest tests/test_integration.py
Requires:   kyber-py, dilithium-py, cryptography installed.

Unlike the per-module unit tests, these exercise the full path an
application would actually use:

    generate keys
        |
        v
    hybrid key establishment  (pqcrypto.hybrid.key_exchange, inside encrypt_file)
        |
        v
    KDF
        |
        v
    AES-256-GCM file encryption
        |
        v
    hybrid signature over the encrypted package
        |
        v
    [transmit / store]
        |
        v
    signature verification
        |
        v
    file decryption
        |
        v
    original file recovered

Every "fails" test in this file asserts the SAME thing at the boundary that
matters: a tampered/incomplete/wrong-key path never yields the original
plaintext back out. Whether it does so by raising FileDecryptorError,
HybridKeyExchangeError, or by hybrid signature verification returning False
is a secondary detail noted in each test's assertion.
"""

from __future__ import annotations

import dataclasses

import pytest

pytest.importorskip("kyber_py", reason="kyber-py is required for integration tests")
pytest.importorskip("dilithium_py", reason="dilithium-py is required for integration tests")

from pqcrypto.encryption.file_decryptor import FileDecryptorError, decrypt_file
from pqcrypto.encryption.file_encryptor import EncryptedFilePackage, encrypt_file
from pqcrypto.hybrid.key_exchange import HybridKeyExchange, HybridKeyExchangeError
from pqcrypto.hybrid.signatures import HybridSigner

SMALL_FILE = b"quarterly-report.txt contents: revenue up 12% quarter over quarter."
EMPTY_FILE = b""
BINARY_FILE = bytes(range(256)) * 1024  # 256 KiB, every byte value represented


@pytest.fixture
def recipient_identity():
    """The recipient's hybrid KEM keypair -- the encryption target."""
    exchange = HybridKeyExchange()
    return exchange.generate_keypair()  # (HybridPublicKey, HybridSecretKey)


@pytest.fixture
def sender_signing_identity():
    """The sender's hybrid signing keypair, used to authenticate packages
    they send -- independent of the recipient's KEM identity."""
    signer = HybridSigner()
    return signer, *signer.generate_keypairs()  # (signer, public_keys, secret_keys)


def _full_send(plaintext: bytes, recipient_public_key, signer, sender_secret_keys):
    """Encrypt `plaintext` for the recipient, then hybrid-sign the resulting
    package's bytes -- the shape a real sender/transport would use."""
    package = encrypt_file(plaintext, recipient_public_key)
    package_bytes = package.to_bytes()
    signature = signer.sign(package_bytes, sender_secret_keys)
    return package, package_bytes, signature


def _full_receive(package_bytes, signature, signer, sender_public_keys, recipient_secret_key):
    """Verify the package's signature, then decrypt it -- raising/returning
    False rather than trusting anything that didn't check out."""
    if not signer.verify(package_bytes, signature, sender_public_keys):
        raise AssertionError("signature verification failed")
    package = EncryptedFilePackage.from_bytes(package_bytes)
    return decrypt_file(package, recipient_secret_key)


# --------------------------------------------------------------- happy path ---

def test_complete_roundtrip_recovers_original_file(recipient_identity, sender_signing_identity):
    recipient_public, recipient_secret = recipient_identity
    signer, sender_public, sender_secret = sender_signing_identity

    package, package_bytes, signature = _full_send(
        SMALL_FILE, recipient_public, signer, sender_secret
    )
    recovered = _full_receive(package_bytes, signature, signer, sender_public, recipient_secret)
    assert recovered == SMALL_FILE


def test_empty_file_roundtrips(recipient_identity, sender_signing_identity):
    recipient_public, recipient_secret = recipient_identity
    signer, sender_public, sender_secret = sender_signing_identity

    _, package_bytes, signature = _full_send(EMPTY_FILE, recipient_public, signer, sender_secret)
    recovered = _full_receive(package_bytes, signature, signer, sender_public, recipient_secret)
    assert recovered == EMPTY_FILE


def test_binary_file_roundtrips(recipient_identity, sender_signing_identity):
    """Every byte value must survive intact -- not just text-safe content."""
    recipient_public, recipient_secret = recipient_identity
    signer, sender_public, sender_secret = sender_signing_identity

    _, package_bytes, signature = _full_send(BINARY_FILE, recipient_public, signer, sender_secret)
    recovered = _full_receive(package_bytes, signature, signer, sender_public, recipient_secret)
    assert recovered == BINARY_FILE


def test_small_and_larger_files_both_work(recipient_identity):
    recipient_public, recipient_secret = recipient_identity
    for size in (1, 64, 1024, 64 * 1024):
        plaintext = bytes(range(256)) * (size // 256 + 1)
        plaintext = plaintext[:size]
        package = encrypt_file(plaintext, recipient_public)
        assert decrypt_file(package, recipient_secret) == plaintext


# -------------------------------------------------------------- tamper guards ---

def test_modified_ciphertext_fails(recipient_identity):
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)

    tampered_bytes = bytearray(package.ciphertext)
    tampered_bytes[0] ^= 0xFF
    tampered = dataclasses.replace(package, ciphertext=bytes(tampered_bytes))

    with pytest.raises(FileDecryptorError):
        decrypt_file(tampered, recipient_secret)


def test_modified_authentication_metadata_fails(recipient_identity):
    """Metadata (algorithm identifiers) is bound in as AES-GCM associated
    data -- changing it must break authentication, not be silently
    accepted."""
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)

    tampered = dataclasses.replace(package, classical_algorithm="X448")

    with pytest.raises(FileDecryptorError):
        decrypt_file(tampered, recipient_secret)


def test_modified_signature_fails(recipient_identity, sender_signing_identity):
    recipient_public, recipient_secret = recipient_identity
    signer, sender_public, sender_secret = sender_signing_identity

    package, package_bytes, signature = _full_send(
        SMALL_FILE, recipient_public, signer, sender_secret
    )
    tampered_sig_bytes = bytearray(signature.ml_dsa_signature)
    tampered_sig_bytes[0] ^= 0xFF
    tampered_signature = dataclasses.replace(signature, ml_dsa_signature=bytes(tampered_sig_bytes))

    assert signer.verify(package_bytes, tampered_signature, sender_public) is False


def test_wrong_recipient_secret_key_fails(recipient_identity):
    _, _ = recipient_identity
    encrypt_exchange = HybridKeyExchange()
    recipient_public, _correct_secret = encrypt_exchange.generate_keypair()
    _wrong_public, wrong_secret = encrypt_exchange.generate_keypair()

    package = encrypt_file(SMALL_FILE, recipient_public)
    with pytest.raises(FileDecryptorError):
        decrypt_file(package, wrong_secret)


def test_wrong_sender_public_key_fails_verification(sender_signing_identity):
    signer, sender_public, sender_secret = sender_signing_identity
    other_public, _other_secret = signer.generate_keypairs()

    signature = signer.sign(SMALL_FILE, sender_secret)
    assert signer.verify(SMALL_FILE, signature, other_public) is False


# ---------------------------------------------------------- format/version ---

def test_unsupported_package_version_rejected(recipient_identity):
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)
    future_version = dataclasses.replace(package, version=package.version + 1)
    with pytest.raises(FileDecryptorError):
        decrypt_file(future_version, recipient_secret)


def test_unsupported_algorithm_identifier_rejected(recipient_identity):
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)
    bad_aead = dataclasses.replace(package, aead_algorithm="AES-128-CBC")
    with pytest.raises(FileDecryptorError):
        decrypt_file(bad_aead, recipient_secret)


def test_incomplete_package_rejected(recipient_identity):
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)
    truncated_pq_ciphertext = dataclasses.replace(
        package, pq_ciphertext=package.pq_ciphertext[: len(package.pq_ciphertext) // 2]
    )
    with pytest.raises(FileDecryptorError):
        decrypt_file(truncated_pq_ciphertext, recipient_secret)


def test_serialized_package_roundtrips_bytes_for_bytes(recipient_identity):
    """to_bytes()/from_bytes() must not lose or corrupt any field needed for
    decryption -- serializing and reparsing must decrypt identically to the
    original in-memory package."""
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)

    reparsed = EncryptedFilePackage.from_bytes(package.to_bytes())
    assert reparsed == package
    assert decrypt_file(reparsed, recipient_secret) == SMALL_FILE


# -------------------------------------------------- component-level failure ---

def test_classical_component_modification_prevents_key_derivation(recipient_identity):
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)

    tampered_classical = bytearray(package.classical_ciphertext)
    tampered_classical[0] ^= 0xFF
    tampered = dataclasses.replace(package, classical_ciphertext=bytes(tampered_classical))

    with pytest.raises(FileDecryptorError):
        decrypt_file(tampered, recipient_secret)


def test_ml_kem_component_modification_prevents_key_derivation(recipient_identity):
    """ML-KEM's implicit rejection means the KEM step itself won't raise for
    a tampered same-length ciphertext -- the wrong derived key must instead
    be caught by AES-GCM authentication failing."""
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)

    tampered_pq = bytearray(package.pq_ciphertext)
    tampered_pq[0] ^= 0xFF
    tampered = dataclasses.replace(package, pq_ciphertext=bytes(tampered_pq))

    with pytest.raises(FileDecryptorError):
        decrypt_file(tampered, recipient_secret)


# -------------------------------------------------------------------- safety ---

def test_failed_authentication_never_returns_plaintext(recipient_identity):
    """Directly confirm the critical invariant: decrypt_file() either raises
    or returns the correct plaintext -- there is no code path that returns
    wrong/partial bytes silently."""
    recipient_public, recipient_secret = recipient_identity
    package = encrypt_file(SMALL_FILE, recipient_public)
    tampered_bytes = bytearray(package.ciphertext)
    tampered_bytes[-1] ^= 0xFF
    tampered = dataclasses.replace(package, ciphertext=bytes(tampered_bytes))

    try:
        result = decrypt_file(tampered, recipient_secret)
    except FileDecryptorError:
        return  # expected: no plaintext produced
    raise AssertionError(f"decrypt_file returned data instead of raising: {len(result)} bytes")
