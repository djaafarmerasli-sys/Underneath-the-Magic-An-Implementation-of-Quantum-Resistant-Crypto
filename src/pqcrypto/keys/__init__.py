"""Key management and persistence for pqcrypto.

An educational key-management layer for generating, storing, rotating, and
deleting ML-KEM, ML-DSA, and classical keypairs. Not a substitute for an HSM,
secure enclave, OS keystore, or production KMS -- see key_storage.py's
module docstring for the specific limitations.
"""

from .key_manager import KeyManager, KeyRecord
from .key_storage import KeyStorage

__all__ = ["KeyManager", "KeyRecord", "KeyStorage"]
