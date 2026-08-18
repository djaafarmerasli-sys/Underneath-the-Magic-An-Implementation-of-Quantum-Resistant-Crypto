"""
serialization.py -- structured (de)serialization for pqcrypto
=================================================================

Provides a small, explicit JSON envelope format for the project's metadata
and encrypted-package structures (key metadata in pqcrypto.keys.key_storage,
encrypted file packages in pqcrypto.encryption.file_encryptor).

DESIGN
------
* JSON, not a custom binary format: human-inspectable, trivial to validate,
  and there is no positional/binary parser of our own to get wrong.
* Binary fields (keys, ciphertexts, nonces, signatures, ...) are base64-encoded
  text inside the JSON object -- never raw bytes concatenated by position.
  Positional binary packing is exactly the kind of "invent a serialization
  format" this project avoids; a keyed JSON field can't be silently
  misaligned by a length changing upstream.
* Every caller-facing envelope built on top of this module is expected to
  include its own explicit `version` and algorithm-identifier fields (see
  file_encryptor.py and key_storage.py) so a decoder can check compatibility
  BEFORE trusting any of the content -- this module enforces that a set of
  `required_fields` is present, but the choice of which fields are required
  belongs to the caller, not to this generic helper.

This module never serializes private key material on its own initiative --
callers (key_storage.py) decide explicitly when secret bytes are serialized.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any


class SerializationError(ValueError):
    """Raised for malformed encodings or missing required fields."""


def encode_bytes(data: bytes) -> str:
    """Base64-encode bytes for embedding in a JSON field."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    return base64.b64encode(bytes(data)).decode("ascii")


def decode_bytes(text: str) -> bytes:
    """Inverse of encode_bytes(). Rejects malformed base64 with a clear error."""
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SerializationError("malformed base64 field") from exc


def dumps(obj: dict[str, Any]) -> bytes:
    """Serialize a JSON-safe dict (binary fields already base64 text, via
    encode_bytes) to canonical, deterministic UTF-8 JSON bytes.

    Sorted keys and compact separators keep the output byte-for-byte
    reproducible for the same logical content, which matters when this output
    is used as associated data for authenticated encryption or as signed data
    (see file_encryptor.py) -- the encoder must not silently vary output for
    identical input.
    """
    if not isinstance(obj, dict):
        raise TypeError(f"obj must be a dict, got {type(obj).__name__}")
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def loads(data: bytes, *, required_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    """Parse UTF-8 JSON bytes back into a dict, validating required fields.

    Raises SerializationError (not a bare json.JSONDecodeError) for any of:
    malformed UTF-8, malformed JSON, a top-level value that isn't an object,
    or a missing required field -- giving callers one exception type to
    handle for "this encoded package is unusable", distinct from a
    programming-error TypeError on the wrong Python type.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    try:
        obj = json.loads(bytes(data).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SerializationError("malformed encoded data: not valid UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise SerializationError(
            "malformed encoded data: expected a JSON object at the top level"
        )
    missing = [name for name in required_fields if name not in obj]
    if missing:
        raise SerializationError(f"missing required field(s): {', '.join(missing)}")
    return obj
