"""Symmetric data/file encryption for pqcrypto.

AES-256-GCM authenticated encryption (pqcrypto.encryption.aes), plus the
file encrypt/decrypt layer (pqcrypto.encryption.file_encryptor /
file_decryptor) that combines it with hybrid key establishment and a KDF.
ML-KEM is never used to encrypt bulk data directly -- see aes.py's module
docstring for why.
"""

from .aes import AESGCMCiphertext, decrypt, encrypt
from .file_decryptor import decrypt_file
from .file_encryptor import EncryptedFilePackage, encrypt_file

__all__ = [
    "encrypt",
    "decrypt",
    "AESGCMCiphertext",
    "encrypt_file",
    "decrypt_file",
    "EncryptedFilePackage",
]
