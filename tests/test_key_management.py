"""Tests for pqcrypto.keys.key_manager and pqcrypto.keys.key_storage.

Run with:   pytest tests/test_key_management.py
Requires:   kyber-py, dilithium-py, cryptography installed.

Every test uses a pytest `tmp_path` (a fresh, automatically-cleaned-up
temporary directory) as the key store -- no test key material is ever
written into the repository itself.
"""

from __future__ import annotations

import pytest

pytest.importorskip("kyber_py", reason="kyber-py is required for key management tests")
pytest.importorskip("dilithium_py", reason="dilithium-py is required for key management tests")

from pqcrypto.keys.key_manager import (
    ALGORITHM_ED25519,
    ALGORITHM_ML_DSA,
    ALGORITHM_ML_KEM,
    ALGORITHM_X25519,
    KeyManager,
    KeyManagerError,
    KeyRecord,
)
from pqcrypto.keys.key_storage import KeyNotFoundError, KeyStorage, KeyStorageError


@pytest.fixture
def storage(tmp_path) -> KeyStorage:
    return KeyStorage(tmp_path / "keystore")


@pytest.fixture
def manager(storage: KeyStorage) -> KeyManager:
    return KeyManager(storage)


# --------------------------------------------------------------- generation ---

def test_generate_ml_kem_keypair_creates_record(manager: KeyManager):
    record = manager.generate_ml_kem_keypair()
    assert isinstance(record, KeyRecord)
    assert record.algorithm == ALGORITHM_ML_KEM
    assert record.security_level == "768"  # the wrapper's default level


def test_generate_ml_dsa_keypair_creates_record(manager: KeyManager):
    record = manager.generate_ml_dsa_keypair()
    assert record.algorithm == ALGORITHM_ML_DSA
    assert record.security_level == "65"


def test_generate_x25519_keypair_creates_record(manager: KeyManager):
    record = manager.generate_x25519_keypair()
    assert record.algorithm == ALGORITHM_X25519


def test_generate_ed25519_keypair_creates_record(manager: KeyManager):
    record = manager.generate_ed25519_keypair()
    assert record.algorithm == ALGORITHM_ED25519


def test_generated_key_ids_are_unique(manager: KeyManager):
    a = manager.generate_ml_kem_keypair()
    b = manager.generate_ml_kem_keypair()
    assert a.key_id != b.key_id


def test_caller_supplied_key_id_is_used(manager: KeyManager):
    record = manager.generate_ml_kem_keypair(key_id="alice-kem-key")
    assert record.key_id == "alice-kem-key"


def test_created_at_timestamp_present(manager: KeyManager):
    record = manager.generate_ml_kem_keypair()
    assert record.created_at  # non-empty ISO 8601 string


def test_injectable_clock_is_used():
    storage = KeyStorage(_tmp_dir_for_clock_test())
    manager = KeyManager(storage, clock=lambda: "2030-01-01T00:00:00+00:00")
    record = manager.generate_ml_kem_keypair()
    assert record.created_at == "2030-01-01T00:00:00+00:00"


def _tmp_dir_for_clock_test():
    import tempfile

    return tempfile.mkdtemp(prefix="pqcrypto-test-")


# ------------------------------------------------------------------ lookup ---

def test_get_public_key_returns_real_material(manager: KeyManager):
    record = manager.generate_ml_kem_keypair()
    public_key = manager.get_public_key(record.key_id)
    assert isinstance(public_key, bytes)
    assert len(public_key) == 1184  # ML-KEM-768 public key size


def test_get_secret_key_returns_real_material(manager: KeyManager):
    record = manager.generate_ml_kem_keypair()
    secret_key = manager.get_secret_key(record.key_id)
    assert isinstance(secret_key, bytes)
    assert len(secret_key) == 2400  # ML-KEM-768 secret key size


def test_get_secret_key_with_passphrase_roundtrips(manager: KeyManager):
    record = manager.generate_x25519_keypair(passphrase="correct horse battery staple")
    secret_key = manager.get_secret_key(record.key_id, passphrase="correct horse battery staple")
    assert len(secret_key) == 32


def test_get_secret_key_wrong_passphrase_fails(manager: KeyManager):
    record = manager.generate_x25519_keypair(passphrase="right-passphrase")
    with pytest.raises(KeyStorageError):
        manager.get_secret_key(record.key_id, passphrase="wrong-passphrase")


def test_get_metadata_matches_generated_record(manager: KeyManager):
    record = manager.generate_ml_dsa_keypair()
    fetched = manager.get_metadata(record.key_id)
    assert fetched == record


def test_list_keys_includes_all_generated(manager: KeyManager):
    a = manager.generate_ml_kem_keypair()
    b = manager.generate_ed25519_keypair()
    listed_ids = {record.key_id for record in manager.list_keys()}
    assert {a.key_id, b.key_id} <= listed_ids


# --------------------------------------------------------------- metadata ---

def test_metadata_never_exposes_key_bytes(manager: KeyManager):
    """KeyRecord (returned by generate_*/get_metadata/list_keys) has no field
    that could carry raw key bytes -- retrieving material is always a
    separate, explicit call."""
    record = manager.generate_ml_kem_keypair()
    field_names = {f for f in vars(record)}
    assert "public_key" not in field_names
    assert "secret_key" not in field_names
    for value in vars(record).values():
        assert not isinstance(value, (bytes, bytearray))


def test_algorithm_metadata_distinguishes_key_types(manager: KeyManager):
    kem_record = manager.generate_ml_kem_keypair()
    dsa_record = manager.generate_ml_dsa_keypair()
    assert kem_record.algorithm != dsa_record.algorithm


def test_parameter_set_metadata_recorded(manager: KeyManager):
    record = manager.generate_ml_kem_keypair(security_level=1024)
    assert record.security_level == "1024"


# ------------------------------------------------------------ missing keys ---

def test_get_public_key_missing_raises(manager: KeyManager):
    with pytest.raises(KeyNotFoundError):
        manager.get_public_key("does-not-exist")


def test_get_metadata_missing_raises(manager: KeyManager):
    with pytest.raises(KeyNotFoundError):
        manager.get_metadata("does-not-exist")


def test_rotate_missing_raises(manager: KeyManager):
    with pytest.raises(KeyNotFoundError):
        manager.rotate("does-not-exist")


# -------------------------------------------------------------- lifecycle ---

def test_delete_removes_key(manager: KeyManager):
    record = manager.generate_ml_kem_keypair()
    manager.delete(record.key_id)
    with pytest.raises(KeyNotFoundError):
        manager.get_public_key(record.key_id)
    with pytest.raises(KeyNotFoundError):
        manager.get_metadata(record.key_id)


def test_delete_already_deleted_key_is_not_an_error(manager: KeyManager):
    record = manager.generate_ml_kem_keypair()
    manager.delete(record.key_id)
    manager.delete(record.key_id)  # must not raise


def test_rotate_generates_new_key_same_algorithm_and_level(manager: KeyManager):
    original = manager.generate_ml_kem_keypair(security_level=1024)
    rotated = manager.rotate(original.key_id)
    assert rotated.key_id != original.key_id
    assert rotated.algorithm == original.algorithm
    assert rotated.security_level == original.security_level
    assert rotated.rotated_from == original.key_id


def test_rotate_does_not_delete_old_key(manager: KeyManager):
    original = manager.generate_ml_kem_keypair()
    manager.rotate(original.key_id)
    assert manager.get_public_key(original.key_id)  # still retrievable


def test_rotate_produces_different_key_material(manager: KeyManager):
    original = manager.generate_x25519_keypair()
    original_public = manager.get_public_key(original.key_id)
    rotated = manager.rotate(original.key_id)
    rotated_public = manager.get_public_key(rotated.key_id)
    assert original_public != rotated_public


# ------------------------------------------------------- duplicate/invalid ---

def test_duplicate_key_id_rejected(manager: KeyManager):
    manager.generate_ml_kem_keypair(key_id="fixed-id")
    with pytest.raises(KeyManagerError):
        manager.generate_ml_kem_keypair(key_id="fixed-id")


def test_invalid_key_id_rejected(manager: KeyManager):
    with pytest.raises(KeyStorageError):
        manager.generate_ml_kem_keypair(key_id="has spaces")


def test_path_traversal_key_id_rejected(manager: KeyManager):
    with pytest.raises(KeyStorageError):
        manager.generate_ml_kem_keypair(key_id="../../etc/passwd")


def test_path_traversal_with_separators_rejected(storage: KeyStorage):
    for bad_id in ("../secret", "a/b", "a\\b", "..", "."):
        with pytest.raises(KeyStorageError):
            storage.load_public_key(bad_id)


# --------------------------------------------------------------- storage ---

def test_public_and_secret_keys_stored_separately(storage: KeyStorage):
    storage.save_public_key("k1", b"public-bytes")
    storage.save_secret_key("k1", b"secret-bytes")
    assert storage.load_public_key("k1") == b"public-bytes"
    assert storage.load_secret_key("k1") == b"secret-bytes"


def test_storage_exists_reflects_any_component(storage: KeyStorage):
    assert storage.exists("k1") is False
    storage.save_public_key("k1", b"public-bytes")
    assert storage.exists("k1") is True


def test_storage_persistence_across_manager_instances(tmp_path):
    base_dir = tmp_path / "shared-store"
    storage_a = KeyStorage(base_dir)
    manager_a = KeyManager(storage_a)
    record = manager_a.generate_ml_kem_keypair()
    public_key = manager_a.get_public_key(record.key_id)

    # A brand-new KeyStorage/KeyManager pointed at the same directory must
    # see exactly the same data -- persistence is on disk, not in memory.
    storage_b = KeyStorage(base_dir)
    manager_b = KeyManager(storage_b)
    assert manager_b.get_public_key(record.key_id) == public_key
    assert manager_b.get_metadata(record.key_id) == record


def test_malformed_metadata_fails_safely(storage: KeyStorage, tmp_path):
    storage.save_public_key("broken", b"public-bytes")
    metadata_path = tmp_path / "keystore" / "metadata" / "broken.json"
    metadata_path.write_bytes(b"{not valid json")
    with pytest.raises(KeyStorageError):
        storage.load_metadata("broken")


def test_list_metadata_raises_on_first_corrupted_entry(storage: KeyStorage, tmp_path):
    storage.save_public_key("good", b"public-bytes")
    from pqcrypto.keys.key_storage import StoredKeyMetadata

    storage.save_metadata(
        "good",
        StoredKeyMetadata(
            key_id="good",
            algorithm="X25519",
            security_level="n/a",
            key_type="keypair",
            created_at="2030-01-01T00:00:00+00:00",
            extra={},
        ),
    )
    (tmp_path / "keystore" / "metadata" / "bad.json").write_bytes(b"not json at all")
    with pytest.raises(KeyStorageError):
        storage.list_metadata()
