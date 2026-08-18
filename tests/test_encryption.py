"""Tests for pqcrypto.encryption.aes (AES-256-GCM authenticated encryption).

Run with:   pytest tests/test_encryption.py
Requires:   cryptography installed.

AES-GCM is an AEAD: decryption either returns exactly the original plaintext
or raises -- there is no third "returned something, but it's wrong" outcome.
These tests pin down that contract for every input dimension the wrapper
documents: key length, plaintext size, nonce/tag/AAD tampering, and wrong keys.
"""

from __future__ import annotations

import pytest

from pqcrypto.encryption.aes import (
    KEY_SIZE,
    NONCE_SIZE,
    AESGCMCiphertext,
    AESGCMError,
    AuthenticationError,
    decrypt,
    encrypt,
)
from pqcrypto.utils import randomness

KEY = randomness.random_bytes(KEY_SIZE)


# --------------------------------------------------------------- happy path ---

def test_roundtrip_recovers_plaintext():
    plaintext = b"the quick brown fox jumps over the lazy dog"
    package = encrypt(plaintext, KEY)
    assert decrypt(package, KEY) == plaintext


def test_empty_plaintext_roundtrips():
    package = encrypt(b"", KEY)
    assert decrypt(package, KEY) == b""


def test_small_plaintext_roundtrips():
    package = encrypt(b"x", KEY)
    assert decrypt(package, KEY) == b"x"


def test_large_plaintext_roundtrips():
    plaintext = bytes(range(256)) * (1024 * 4)  # 1 MiB, all byte values present
    package = encrypt(plaintext, KEY)
    assert decrypt(package, KEY) == plaintext


def test_arbitrary_binary_plaintext_roundtrips():
    """Every byte value (0x00-0xFF), including NUL and non-UTF8 sequences,
    must survive the roundtrip untouched."""
    plaintext = bytes(range(256))
    package = encrypt(plaintext, KEY)
    assert decrypt(package, KEY) == plaintext


def test_associated_data_roundtrips():
    plaintext = b"secret payload"
    aad = b"format=v1;alg=AES-256-GCM"
    package = encrypt(plaintext, KEY, associated_data=aad)
    assert decrypt(package, KEY, associated_data=aad) == plaintext


# ------------------------------------------------------------------ key size ---

def test_exact_32_byte_key_accepted():
    key = randomness.random_bytes(32)
    package = encrypt(b"data", key)
    assert decrypt(package, key) == b"data"


def test_short_key_rejected():
    with pytest.raises(AESGCMError):
        encrypt(b"data", randomness.random_bytes(16))


def test_long_key_rejected():
    with pytest.raises(AESGCMError):
        encrypt(b"data", randomness.random_bytes(64))


def test_wrong_type_key_rejected():
    with pytest.raises(TypeError):
        encrypt(b"data", "not-bytes")


# --------------------------------------------------------------- randomness ---

def test_repeated_encryptions_use_different_nonces():
    plaintext = b"same plaintext every time"
    package_a = encrypt(plaintext, KEY)
    package_b = encrypt(plaintext, KEY)
    assert package_a.nonce != package_b.nonce
    assert package_a.ciphertext != package_b.ciphertext


def test_nonce_has_expected_size():
    package = encrypt(b"data", KEY)
    assert len(package.nonce) == NONCE_SIZE == 12


# -------------------------------------------------------------- tamper guards ---

def test_tampered_ciphertext_rejected():
    package = encrypt(b"authentic data", KEY)
    tampered_bytes = bytearray(package.ciphertext)
    tampered_bytes[0] ^= 0xFF
    tampered = AESGCMCiphertext(nonce=package.nonce, ciphertext=bytes(tampered_bytes))
    with pytest.raises(AuthenticationError):
        decrypt(tampered, KEY)


def test_tampered_nonce_rejected():
    package = encrypt(b"authentic data", KEY)
    tampered_nonce = bytearray(package.nonce)
    tampered_nonce[0] ^= 0xFF
    tampered = AESGCMCiphertext(nonce=bytes(tampered_nonce), ciphertext=package.ciphertext)
    with pytest.raises(AuthenticationError):
        decrypt(tampered, KEY)


def test_tampered_authentication_tag_rejected():
    """The final TAG_SIZE bytes of `ciphertext` are the AEAD tag -- flipping
    a bit there must fail authentication exactly like a tampered body byte."""
    package = encrypt(b"authentic data", KEY)
    tampered_bytes = bytearray(package.ciphertext)
    tampered_bytes[-1] ^= 0xFF
    tampered = AESGCMCiphertext(nonce=package.nonce, ciphertext=bytes(tampered_bytes))
    with pytest.raises(AuthenticationError):
        decrypt(tampered, KEY)


def test_modified_associated_data_rejected():
    package = encrypt(b"authentic data", KEY, associated_data=b"original-context")
    with pytest.raises(AuthenticationError):
        decrypt(package, KEY, associated_data=b"different-context")


def test_missing_associated_data_rejected():
    """AAD supplied at encryption time but omitted at decryption time must
    fail authentication rather than silently succeeding without it."""
    package = encrypt(b"authentic data", KEY, associated_data=b"required-context")
    with pytest.raises(AuthenticationError):
        decrypt(package, KEY)


def test_wrong_key_fails():
    package = encrypt(b"authentic data", KEY)
    wrong_key = randomness.random_bytes(KEY_SIZE)
    with pytest.raises(AuthenticationError):
        decrypt(package, wrong_key)


# ------------------------------------------------------- malformed package ---

def test_decrypt_rejects_non_package_type():
    with pytest.raises(TypeError):
        decrypt(b"not-an-AESGCMCiphertext", KEY)


def test_decrypt_rejects_wrong_length_nonce():
    package = encrypt(b"data", KEY)
    malformed = AESGCMCiphertext(nonce=package.nonce[:4], ciphertext=package.ciphertext)
    with pytest.raises(AESGCMError):
        decrypt(malformed, KEY)


def test_encrypt_rejects_non_bytes_plaintext():
    with pytest.raises(TypeError):
        encrypt("not-bytes", KEY)


def test_encrypt_rejects_non_bytes_associated_data():
    with pytest.raises(TypeError):
        encrypt(b"data", KEY, associated_data="not-bytes")
