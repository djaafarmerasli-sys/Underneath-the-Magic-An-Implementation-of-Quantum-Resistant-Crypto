"""
file_encryption.py -- end-to-end hybrid file encryption demo
==================================================================

Run with:   python examples/file_encryption.py

Demonstrates the complete workflow this project builds toward:

    demo file
        |
        v
    hybrid key establishment (X25519 + ML-KEM)  -- pqcrypto.hybrid.key_exchange
        |
        v
    KDF                                          -- pqcrypto.hybrid.kdf
        |
        v
    AES-256-GCM                                  -- pqcrypto.encryption.aes
        |
        v
    encrypted package (with algorithm/version metadata)
        |
        v
    hybrid signature over the package             -- pqcrypto.hybrid.signatures
        |
        v
    [ package + signature is what actually gets stored/transmitted ]
        |
        v
    signature verification
        |
        v
    decrypt
        |
        v
    restored file == original file

Uses a small, self-generated demo file (written to a temporary directory,
cleaned up on exit) rather than requiring the user to supply a real file.

SAFE OUTPUT ONLY: never prints plaintext contents, keys, private keys,
shared secrets, or the full signature -- only sizes and pass/fail status.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pqcrypto.encryption.file_decryptor import FileDecryptorError, decrypt_file
from pqcrypto.encryption.file_encryptor import EncryptedFilePackage, encrypt_file
from pqcrypto.hybrid.key_exchange import HybridKeyExchange
from pqcrypto.hybrid.signatures import HybridSigner

DEMO_CONTENT = (
    b"This is a demonstration file for pqcrypto's hybrid file-encryption "
    b"pipeline. It is not sensitive; it exists purely to be encrypted, "
    b"signed, transmitted, verified, and decrypted in this example.\n"
)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="pqcrypto-demo-") as tmp_dir:
        demo_path = Path(tmp_dir) / "demo.txt"
        demo_path.write_bytes(DEMO_CONTENT)
        print(f"Demo file size: {demo_path.stat().st_size} bytes")

        # --- Recipient generates a hybrid KEM identity to receive files. ---
        kem_exchange = HybridKeyExchange()
        recipient_public, recipient_secret = kem_exchange.generate_keypair()

        # --- Sender generates a hybrid signing identity to authenticate
        #     what they send. ---
        signer = HybridSigner()
        sender_public, sender_secret = signer.generate_keypairs()

        # --- Encrypt the file for the recipient. ---
        plaintext = demo_path.read_bytes()
        package = encrypt_file(plaintext, recipient_public)
        print(f"Encrypted package ciphertext size: {len(package.ciphertext)} bytes")
        print(f"KEM ciphertext components: classical={len(package.classical_ciphertext)} bytes, "
              f"ML-KEM={len(package.pq_ciphertext)} bytes")

        # --- Sign the serialized package so the recipient can authenticate
        #     its origin, independent of AES-GCM's own tamper protection. ---
        package_bytes = package.to_bytes()
        signature = signer.sign(package_bytes, sender_secret)
        print(f"Hybrid signature: ML-DSA={len(signature.ml_dsa_signature)} bytes, "
              f"classical={len(signature.classical_signature)} bytes")

        # --- Recipient verifies the signature, then decrypts. ---
        signature_valid = signer.verify(package_bytes, signature, sender_public)
        print(f"Signature verified: {signature_valid}")
        assert signature_valid

        received_package = EncryptedFilePackage.from_bytes(package_bytes)
        restored = decrypt_file(received_package, recipient_secret)
        restored_path = Path(tmp_dir) / "demo.restored.txt"
        restored_path.write_bytes(restored)

        round_trip_ok = restored == plaintext
        print(f"Restored file matches original: {round_trip_ok}")
        assert round_trip_ok

        # --- Now show the failure path: a modified encrypted package must
        #     NOT decrypt successfully. ---
        tampered_package_bytes = bytearray(package_bytes)
        # Flip a byte inside the JSON payload -- likely to land in the
        # base64-encoded ciphertext/nonce/KEM-ciphertext fields.
        tampered_package_bytes[len(tampered_package_bytes) // 2] ^= 0xFF
        try:
            tampered_package = EncryptedFilePackage.from_bytes(bytes(tampered_package_bytes))
            decrypt_file(tampered_package, recipient_secret)
        except (FileDecryptorError, ValueError) as exc:
            print(f"Tampered package correctly rejected: {type(exc).__name__}")
        else:
            raise AssertionError("a tampered package must never decrypt successfully")


if __name__ == "__main__":
    main()
