# Security Analysis

This document analyzes `pqcrypto`'s security properties at four distinct
levels, deliberately kept separate because conflating them is a common
source of overclaiming in cryptographic software:

- **Algorithm-level security** — properties of ML-KEM/ML-DSA/AES-GCM/HKDF/
  X25519/Ed25519 as mathematical constructions, independent of any specific
  implementation.
- **Implementation-level security** — properties of the specific libraries
  (`kyber-py`, `dilithium-py`, `cryptography`) and this project's own code.
- **Protocol-level security** — properties of how this project *composes*
  those algorithms (the hybrid constructions, the file format).
- **Operational security** — properties that depend on how the software is
  deployed and used (key storage, passphrase handling, environment).

**This project is not "secure" in an absolute sense, has not been
independently audited, and must not be treated as production cryptographic
infrastructure.** See [`README.md#limitations`](../README.md#10-limitations).

## 1. ML-KEM security assumptions

Algorithm-level: security rests on the Module Learning-With-Errors (Module-
LWE) problem being hard for both classical and quantum algorithms at the
standardized parameter sizes (512/768/1024). This is NIST's own
standardization judgment (FIPS 203, 2024) following a multi-year public
competition and cryptanalysis effort. It is a *believed-hard* assumption,
not a proof — see `cryptography.md`'s framing at the top of that document.

## 2. ML-DSA security assumptions

Algorithm-level: security rests on Module-LWE plus a related lattice
problem, combined via a Fiat-Shamir-with-aborts signing construction (FIPS
204, 2024). Same caveat as above: believed-hard, publicly vetted through
NIST's process, not proven unconditionally secure.

## 3. AES-256-GCM security properties

Algorithm-level: AES-256-GCM provides both confidentiality (IND-CPA under a
random key) and integrity/authenticity (INT-CTXT) **provided the nonce is
never reused with the same key**. This project's `encrypt()` enforces fresh,
cryptographically random nonce generation on every call — see
`encryption/aes.py`. GCM's authentication tag is verified before any
plaintext is returned; there is no partial-output failure mode in this
wrapper (`decrypt()` either returns the full correct plaintext or raises
`AuthenticationError` — see `tests/test_encryption.py`).

## 4. KDF security role

`hybrid/kdf.py` uses HKDF-SHA256 (RFC 5869) to: (a) turn the non-uniform
raw X25519 ECDH output into uniformly distributed key bytes, and (b)
combine two independent secrets (classical + PQ, or a hybrid session key +
a file-specific context) into one derived key with mandatory domain
separation (`info`/`context`). HKDF's security (as a pseudorandom-function
family, under the extract-then-expand paradigm) is a standard, published
cryptographic result — this project does not invent or modify the
construction.

## 5. Hybrid composition assumptions

Protocol-level, and the most important place this document draws a
careful line: concatenating two independently-established secrets through
an HKDF combiner (`derive_hybrid_session_key`), or requiring both signatures
to independently verify (`HybridSigner.verify`'s `AND` policy), is a
**standard, widely-used construction shape** — the same shape TLS 1.3's
hybrid PQC key-exchange modes use. It is **not**, by itself, a
peer-reviewed, formally-proven "hybrid security" theorem covering every
possible pairing of algorithms this code *could* be configured with. The
specific combination this project ships (X25519 + ML-KEM;
Ed25519 + ML-DSA) is a reasonable, conventional choice, but this project
does not claim a formal composition proof for it — see
`hybrid/key_exchange.py`'s and `hybrid/signatures.py`'s module docstrings
for the same caveat stated at the point of use.

## 6. Authentication properties

Two independent authentication mechanisms exist in this project, serving
different scopes:

- **AES-GCM's authentication tag** authenticates a single encrypted
  package's ciphertext and bound metadata against the specific AES key used
  — it says "this package's bytes are exactly what was encrypted under this
  key," not "this package came from a specific identity."
- **Hybrid signatures** (`hybrid/signatures.py`) authenticate a message
  against a signer's long-lived public key identity — this is what
  `examples/file_encryption.py` layers on top of an encrypted package's
  serialized bytes to answer "who sent this."

Neither substitutes for the other; `file_encryptor.py`/`file_decryptor.py`
only provide the first. An application wanting sender authentication for
encrypted files must explicitly add a hybrid-signature layer, as the example
demonstrates.

## 7. Integrity properties

Ciphertext, nonce, and declared algorithm/version metadata are all
authenticated together via AES-GCM's associated-data binding (see
`EncryptedFilePackage.associated_data()`), so none of those fields can be
independently swapped onto a captured, otherwise-valid ciphertext without
detection.

## 8. Key-management limitations

`keys/key_storage.py` is an **educational** persistence layer:

- Without an explicit `passphrase`, secret keys are stored in **plaintext**
  on disk, protected only by filesystem permissions (and on Windows,
  `os.chmod` does not provide POSIX-style per-user enforcement — see that
  module's docstring).
- With a `passphrase`, keys are encrypted at rest with scrypt (RFC 7914) +
  AES-256-GCM — a reasonable password-based construction, but scrypt's
  security depends entirely on passphrase strength, which this project has
  no way to enforce or measure.
- No hardware-backed key protection (HSM, TPM, secure enclave), no OS
  keystore integration (DPAPI/Keychain/keyring), and no key-escrow or
  multi-party authorization model.

## 9. Randomness requirements

ML-KEM and ML-DSA manage their own algorithm-specific randomness internally
per their FIPS specifications — this project never seeds them. For its own
supporting needs (salts, key IDs), `utils/randomness.py` uses Python's
`secrets` module (OS CSPRNG). `random.random()`/`random.randbytes()` (the
Mersenne Twister, predictable from a handful of outputs) are never used
anywhere in `src/pqcrypto/` for security-relevant randomness.

## 10. Nonce requirements

See §3 above and `encryption/aes.py`'s module docstring: fresh random
96-bit nonce per encryption call, always returned bundled with the
ciphertext, never caller-suppliable.

## 11. Serialization risks

`utils/serialization.py`'s JSON envelope rejects malformed UTF-8, malformed
JSON, non-object top-level values, and missing required fields with a
single `SerializationError` type rather than letting a raw
`json.JSONDecodeError` or `UnicodeDecodeError` propagate. Binary fields are
base64-encoded rather than positionally packed, so a length change upstream
cannot silently misalign adjacent fields the way a hand-rolled binary format
could. This module does not, by itself, protect against a *structurally
valid* but semantically wrong package (e.g. a real ciphertext for the wrong
recipient) — that is caught downstream, by AEAD authentication and/or hybrid
key recovery failing, not by the serialization layer.

## 12. Side-channel limitations

**This is the single most important implementation-level caveat in this
project.** `kyber-py` and `dilithium-py` are educational, pure-Python
implementations, written for algorithmic clarity. They make **no
constant-time guarantee** and **no side-channel-resistance guarantee** —
timing, cache-access patterns, or power/EM analysis could plausibly leak
information about secret keys to an attacker with the right kind of
measurement access, in a way a production, hardened implementation (e.g.
liboqs's optimized/constant-time backends) is specifically engineered to
prevent. `cryptography` (pyca)'s primitives (AES-GCM, X25519, Ed25519, HKDF,
scrypt) are backed by OpenSSL and are constant-time to the extent OpenSSL
itself provides that guarantee — a materially different assurance level than
the pure-Python PQC backends.

## 13. Implementation risks

This project's own code (the wrapper/hybrid/file-format layers) has not
been independently audited. It has been extensively unit- and
integration-tested (180+ tests as of this writing, covering round-trip,
wrong-key, tampering, and malformed-input cases for every module — see
`tests/`), but passing tests demonstrate absence of the specific failures
tested for, not absence of all possible flaws.

## 14. Dependency risks

`kyber-py` and `dilithium-py` are relatively young, single/small-maintainer,
pure-Python packages implementing very recently finalized standards (FIPS
203/204, both 2024) — they carry more implementation-maturity risk than a
20-plus-year-old library. `cryptography` (pyca) is a mature, widely-audited,
OpenSSL-backed library and carries substantially lower implementation risk
for the classical primitives it provides.

## 15. Known limitations of educational Python cryptographic implementations

Beyond the side-channel point in §12: pure-Python implementations of
lattice-based cryptography are also meaningfully slower than optimized
(often C/assembly, sometimes hardware-accelerated) production
implementations — see `benchmarks/benchmark_kem.py` and
`benchmarks/benchmark_signatures.py` for this project's own measured
numbers, which should not be read as representative of production PQC
performance.

## 16. Future security improvements

Concrete, honestly-scoped directions this project could take (none of which
are implemented today): swap `kyber-py`/`dilithium-py` for a constant-time
backend (e.g. `liboqs`-based bindings) without changing the public
`MLKEM`/`MLDSA` interface, since the wrapper boundary was specifically
designed to make that swap isolated to two files; add OS-keystore-backed
storage as an alternative `KeyStorage` implementation; add a streaming/
chunked AEAD construction for large-file encryption (see
`file_encryptor.py`'s documented streaming limitation); and pursue an actual
third-party security review before any of this code is considered for use
beyond learning and experimentation.
