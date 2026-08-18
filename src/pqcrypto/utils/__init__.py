"""Shared utilities for pqcrypto: serialization and secure-randomness helpers.

Used internally by pqcrypto.keys.key_storage and pqcrypto.encryption.aes /
file_encryptor. Import the specific submodule you need
(``pqcrypto.utils.randomness`` / ``pqcrypto.utils.serialization``) -- this
package intentionally re-exports nothing, since both submodules are small
enough that a qualified import stays clear.
"""
