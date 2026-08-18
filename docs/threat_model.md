# Threat Model

This document describes what `pqcrypto` defends, against whom, under what
assumptions, and — just as importantly — what it explicitly does not
address. See [`security_analysis.md`](security_analysis.md) for a
per-algorithm breakdown of security properties, and
[`architecture.md`](architecture.md#6-trust-boundaries) for where trust
boundaries sit in the code.

## Assets

What this project's cryptography exists to protect:

| Asset | Where it lives in this codebase |
|---|---|
| Plaintext files | Input to `encryption/file_encryptor.py`, output of `file_decryptor.py` |
| Private/secret keys (ML-KEM, ML-DSA, X25519, Ed25519) | In-memory `HybridSecretKey`/raw key bytes; at rest via `keys/key_storage.py` |
| Shared secrets (KEM outputs, hybrid session keys) | Transient, in-memory only inside `hybrid/key_exchange.py` and callers |
| Signatures | `hybrid/signatures.py`'s `HybridSignature` |
| Encrypted packages | `encryption/file_encryptor.py`'s `EncryptedFilePackage` |
| Non-secret metadata (algorithm IDs, format version, key IDs, timestamps) | `KeyRecord`, `EncryptedFilePackage`'s plain fields |

Metadata is listed as an asset in the sense that its *integrity* matters
(tampering with a declared algorithm identifier must be detected — see
"downgrade attacks" below) even though it carries no confidentiality
requirement of its own.

## Attackers considered

- **Passive network eavesdropper.** Can read every byte transmitted
  (ciphertext, KEM ciphertexts, signatures, public keys) but cannot modify
  or inject traffic. Defended against by design: none of the transmitted
  data is sufficient to recover plaintext or private keys without the
  intended recipient's secret key.
- **Active network attacker.** Can additionally modify, replay, reorder, or
  inject traffic. Defended against via AES-GCM authentication (any
  ciphertext/nonce/AAD modification is detected) and hybrid signature
  verification (any modified/forged/replayed-with-different-content message
  fails verification).
- **Ciphertext/package modification attacker.** A specific case of the
  above, called out separately because it's the primary thing
  `tests/test_integration.py` and the AEAD/signature tamper tests directly
  exercise: an attacker who has captured a legitimate `EncryptedFilePackage`
  or `HybridSignature` and modifies bytes within it (ciphertext, nonce, KEM
  ciphertext components, algorithm identifiers, or signature bytes) before
  it reaches the recipient.
- **Attacker with future quantum computing capability.** Cannot break
  ML-KEM or ML-DSA (as far as currently known — see
  `security_analysis.md`), and cannot break the hybrid constructions as long
  as ML-KEM/ML-DSA individually hold, even if that same attacker CAN break
  the classical (X25519/Ed25519) component with Shor's algorithm. This is
  the central motivation for the hybrid design.
- **Compromised endpoint.** Explicitly a **non-goal** — see below.

## Security goals

- **Confidentiality**: plaintext file contents are recoverable only by the
  holder of the matching hybrid secret key.
- **Integrity**: any modification to an encrypted package's ciphertext,
  nonce, or bound metadata is detected (AES-GCM authentication failure)
  rather than silently producing corrupted plaintext.
- **Authenticity**: a hybrid-signed message's origin is verifiable by anyone
  holding the signer's public keys, and cannot be forged without both
  secret keys.
- **Key confidentiality**: shared secrets and derived AES keys are never
  logged, printed, or included in exception messages anywhere in this
  codebase (see the "no secret logging" requirement enforced throughout
  `src/pqcrypto/`).
- **Downgrade resistance**: `EncryptedFilePackage`/`HybridCiphertext`/
  `HybridSignature` all carry explicit algorithm identifiers and a format
  version, checked before any cryptographic operation proceeds — an
  attacker cannot cause a recipient to silently accept a weaker algorithm
  or an unsupported version.
- **Algorithm agility**: because algorithm/version identifiers are explicit
  and validated rather than assumed, this project's format can add support
  for new algorithms or parameter sets in the future without breaking the
  ability to correctly reject (rather than misinterpret) older or
  differently-configured packages.

## Non-goals

- **A compromised endpoint.** If an attacker has arbitrary code execution
  on the machine holding plaintext or private key material — before
  encryption, after decryption, or via a compromised Python
  process/interpreter — no cryptographic design in this project (or any
  other) protects that data. Cryptography protects data *in transit or at
  rest against parties who don't control an endpoint*; it is not a
  substitute for endpoint security, OS-level access control, or supply-chain
  integrity of the Python environment itself.
- **Traffic analysis resistance.** This project does not hide *that* an
  encrypted exchange happened, its approximate size, or its timing.
- **Availability.** No denial-of-service protections are in scope.
- **Formal verification.** No component of this project has been
  machine-checked against a formal security model.

## Attack analysis

- **Classical public-key compromise by a future quantum computer.** Covered
  by the hybrid design (`hybrid/key_exchange.py`, `hybrid/signatures.py`):
  the session key/signature validity depends on ML-KEM/ML-DSA even if
  X25519/Ed25519 are later broken. Not covered: any protocol or system in
  the user's broader environment that uses *classical-only* cryptography
  outside this project's scope.
- **Store-now-decrypt-later.** An adversary recording today's
  `EncryptedFilePackage` traffic and decrypting it once a
  cryptographically-relevant quantum computer exists is exactly the threat
  the ML-KEM component of the hybrid key exchange defends against — the
  session key stays confidential even if X25519 alone would eventually
  fall. This defense holds only for traffic that actually went through the
  hybrid path; classical-only historical traffic outside this project
  remains exposed by definition (the migration hasn't happened yet for it).
- **Ciphertext modification.** Detected by AES-GCM's authentication tag;
  `file_decryptor.py` never returns plaintext when the tag doesn't verify
  (see `tests/test_encryption.py`'s and `tests/test_integration.py`'s
  tamper tests).
- **Signature forgery.** ML-DSA and Ed25519 are each independently
  forgery-resistant under their respective hardness assumptions; the hybrid
  policy (`ml_dsa_valid AND classical_valid`) additionally means forging a
  hybrid signature requires breaking *both* algorithms, not just one.
- **Key theft.** Out of scope for the cryptographic protocol itself to
  prevent (see "compromised endpoint" above) — this project's mitigation is
  limited to `keys/key_storage.py`'s optional passphrase-based
  encryption-at-rest (scrypt + AES-256-GCM), which raises the bar for an
  attacker who obtains the storage directory's files but not the
  passphrase. It does **not** protect against an attacker who can read
  process memory while the key is in use, or who captures the passphrase
  itself.
- **Nonce misuse.** `encryption/aes.py`'s `encrypt()` always generates its
  own fresh random nonce and returns it bundled with the ciphertext — there
  is no code path in this project that lets a caller supply or reuse a
  nonce, which is the standard mitigation for AES-GCM's catastrophic
  nonce-reuse failure mode.
- **Downgrade attacks.** `HybridCiphertext.respond()` and
  `HybridSignature`'s `verify()` both explicitly check algorithm identifiers
  and format version before proceeding, and fail closed (raise, or return
  `False`) on any mismatch — see `test_hybrid_kem.py`'s and
  `test_hybrid_signatures.py`'s identifier-mismatch tests.
- **Malformed package attacks.** `file_decryptor.py` validates package
  version and declared algorithms before attempting key recovery;
  `EncryptedFilePackage.from_bytes`/`utils.serialization.loads` reject
  malformed JSON, missing required fields, and malformed base64 rather than
  crashing unpredictably or partially parsing. See
  `test_integration.py::test_incomplete_package_rejected` and
  `test_unsupported_*_rejected`.

This project does **not** claim to solve every threat listed above
perfectly or completely — each bullet describes the specific mechanism
involved and its actual, tested scope, not a blanket security guarantee.
