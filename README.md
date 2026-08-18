# Underneath the Magic : An Implementation of Quantum Resistant Crypto

An educational/research Python project demonstrating post-quantum cryptography
(PQC), classical cryptography, and hybrid classical+PQC designs, built around
the NIST-standardized **ML-KEM** (FIPS 203) and **ML-DSA** (FIPS 204)
algorithms. 

Part of my Underneath the Magic Project . 

> **This is not production cryptographic software.** See
> [Limitations](#limitations) and [`docs/security_analysis.md`](docs/security_analysis.md)
> before relying on any part of it for anything beyond learning and
> experimentation.

## 1. Project overview

This project builds a modular demonstration of post-quantum cryptography,
comparing it against classical public-key cryptography and showing how the
two can be combined during the multi-year transition period the industry is
now in. It exists to teach the concepts hands-on — key encapsulation,
digital signatures, hybrid key establishment, key derivation, authenticated
symmetric encryption, key management, and performance trade-offs — not to
ship a cryptography library.

Every cryptographic primitive is provided by a vetted third-party
implementation (`kyber-py`, `dilithium-py`, `cryptography`/pyca); this
project never implements lattice mathematics, elliptic-curve arithmetic, or
block-cipher internals itself. What it *does* write is the wrapper layer,
the hybrid-composition logic, the key-management and file-format code, the
tests, the benchmarks, and the documentation around all of it.

## 2. Problem: the quantum threat to public-key cryptography

Classical public-key cryptography in wide use today — RSA, Diffie-Hellman,
elliptic-curve cryptography (ECDH, ECDSA, Ed25519, X25519) — derives its
security from problems believed to be *classically* hard: factoring large
integers, and computing discrete logarithms (including over elliptic
curves). **Shor's algorithm**, a quantum algorithm published in 1994, solves
both problems in polynomial time on a sufficiently large, fault-tolerant
quantum computer. No such machine exists yet at the scale needed to break
real-world key sizes, but if one is built, every RSA/DH/ECC key in use
becomes retroactively breakable.

Symmetric cryptography (AES) and hash functions are affected very
differently: **Grover's algorithm** gives a quantum computer at best a
*quadratic* speedup against a symmetric cipher's keyspace, not the
exponential break Shor's algorithm gives against public-key math. AES-256's
2^256 keyspace absorbs that quadratic hit and still leaves roughly 2^128 of
effective quantum-resistant security — comfortably infeasible. This is why
this project keeps AES-256 as its symmetric primitive and only replaces the
*public-key* layer.

**Store-now-decrypt-later**: an adversary does not need a quantum computer
today to benefit from one tomorrow. They can record encrypted traffic or
exfiltrated ciphertext now, and decrypt it retroactively once a
cryptographically-relevant quantum computer exists. For data that must stay
confidential for years or decades (health records, government
communications, long-lived financial/legal records), this makes migration to
post-quantum cryptography an *urgent-even-though-the-attack-doesn't-exist-yet*
problem — waiting until quantum computers arrive is already too late for
data captured before the migration.

## 3. Algorithms

All algorithm names follow current NIST-standardized terminology.

| Purpose | Algorithm | Standard | Historical name |
|---|---|---|---|
| Key encapsulation (PQC) | **ML-KEM** | FIPS 203 (2024) | CRYSTALS-Kyber |
| Digital signatures (PQC) | **ML-DSA** | FIPS 204 (2024) | CRYSTALS-Dilithium |
| Key establishment (classical) | X25519 | RFC 7748 | — |
| Digital signatures (classical) | Ed25519 | RFC 8032 | — |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D | — |
| Key derivation | HKDF-SHA256 | RFC 5869 | — |

- **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism) lets two
  parties agree on a shared secret over a public channel. Its security rests
  on the Module Learning-With-Errors (Module-LWE) problem over structured
  lattices — a different hardness assumption than factoring/discrete-log, so
  Shor's algorithm does not apply to it. See `src/pqcrypto/kem/ml_kem.py`.
- **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm) lets a
  secret-key holder prove authorship of a message. Also lattice/Module-LWE
  based, via a "Fiat-Shamir with aborts" signing construction. See
  `src/pqcrypto/signatures/ml_dsa.py`.
- **AES-256-GCM** is this project's sole bulk-encryption primitive — an
  Authenticated Encryption with Associated Data (AEAD) mode providing both
  confidentiality and integrity. ML-KEM/ML-DSA are never used to touch file
  contents directly. See `src/pqcrypto/encryption/aes.py`.
- **X25519 / Ed25519** are the classical baselines used for benchmarking and
  as one half of every hybrid construction in this project.
- **HKDF-SHA256** combines independently-established secrets (e.g. an X25519
  shared secret and an ML-KEM shared secret) into one uniformly-random
  session key — never by concatenating and truncating. See
  `src/pqcrypto/hybrid/kdf.py`.

"Believed resistant to quantum attack" is a statement about the current
state of cryptanalysis, not a mathematical proof — see
[`docs/cryptography.md`](docs/cryptography.md) for the precise distinction
this project draws throughout.

## 4. Architecture

```text
quantum-resistant-crypto/
│
├── README.md
├── LICENSE
├── requirements.txt
├── pyproject.toml
│
├── src/pqcrypto/
│   ├── kem/            ML-KEM (ml_kem.py) + classical X25519 KEM (classical_kem.py)
│   ├── signatures/      ML-DSA (ml_dsa.py) + classical Ed25519 (classical_signature.py)
│   ├── hybrid/          key_exchange.py, signatures.py, kdf.py -- combine classical + PQC
│   ├── encryption/      aes.py (AES-256-GCM) + file_encryptor.py / file_decryptor.py
│   ├── keys/            key_manager.py, key_storage.py -- key lifecycle + persistence
│   └── utils/           serialization.py, randomness.py -- shared low-level helpers
│
├── benchmarks/          benchmark_kem.py, benchmark_signatures.py,
│                        benchmark_encryption.py, benchmark_classical.py
├── tests/                one test module per source module, plus test_integration.py
├── examples/             basic_kem.py, signing.py, hybrid_exchange.py, file_encryption.py
├── docs/                 architecture, cryptography, threat model, security analysis,
│                        benchmarking methodology, migration guide
└── data/benchmark_results/   JSON output from the benchmark scripts (generated, not fabricated)
```

**Layering** (each layer depends only on the one below it):

```text
  keys/            file_encryptor.py / file_decryptor.py
    |                        |
    v                        v
  kem/, signatures/   <---   hybrid/  (key_exchange.py, signatures.py, kdf.py)
    |                        |
    v                        v
  third-party libraries   encryption/ (aes.py)
  (kyber-py, dilithium-py,     |
   cryptography)               v
                          utils/ (serialization.py, randomness.py)
```

Third-party cryptographic APIs are isolated behind this project's own
wrapper classes (`MLKEM`, `MLDSA`, `ClassicalKEM`, `ClassicalSignature`) —
nothing outside `src/pqcrypto/kem/` and `src/pqcrypto/signatures/` imports
`kyber_py`, `dilithium_py`, or `cryptography` primitives directly. If a
backend library's API changes, only the corresponding wrapper needs editing.
See [`docs/architecture.md`](docs/architecture.md) for the full data-flow
diagrams (encryption, decryption, key exchange, key management).

## 5. Installation

Requires **Python 3.11+**.

```bash
# from the project root
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt        # runtime dependencies only
# or, for development (adds pytest):
pip install -r requirements-dev.txt

# editable install, so `import pqcrypto` works from anywhere and console
# scripts/examples can be run without manipulating sys.path:
pip install -e .
```

## 6. Running tests

```bash
pytest
```

`tests/conftest.py` adds `src/` to `sys.path`, so the full suite also runs
directly from a fresh checkout without an editable install. Every
cryptographic module has a corresponding `tests/test_*.py` with happy-path,
round-trip, wrong-key, tampering, malformed-input, and API-validation
coverage; `tests/test_integration.py` exercises the complete
generate-keys → hybrid key establishment → encrypt → sign → verify → decrypt
pipeline end to end.

## 7. Examples

Run any example directly (after an editable install, or with `src/` on
`PYTHONPATH`):

```bash
python examples/basic_kem.py         # ML-KEM key encapsulation in isolation
python examples/signing.py           # ML-DSA signing + a tampering demo
python examples/hybrid_exchange.py   # X25519 + ML-KEM hybrid key exchange
python examples/file_encryption.py   # full hybrid file encrypt/sign/verify/decrypt pipeline
```

None of the examples print private keys, shared secrets, or plaintext —
only sizes, algorithm identifiers, and pass/fail results, so they're safe to
run and share output from.

## 8. Benchmarking

```bash
python benchmarks/benchmark_kem.py          # ML-KEM-512/768/1024 timings + sizes
python benchmarks/benchmark_signatures.py   # ML-DSA-44/65/87 + Ed25519 timings + sizes
python benchmarks/benchmark_encryption.py   # AES-256-GCM throughput at 1KiB-100MiB
python benchmarks/benchmark_classical.py    # X25519 vs ML-KEM, Ed25519 vs ML-DSA, side by side
```

Each script warms up before timing, takes many independent repetitions, and
reports mean/median/stdev/ops-per-second plus artifact sizes. Results print
as a console table and are written as machine-readable JSON to
`data/benchmark_results/<script-name>.json`, alongside environment metadata
(Python version, platform, installed library versions). **No benchmark
numbers in this repository's history are fabricated or hand-edited** — every
number in `data/benchmark_results/` was produced by actually running the
corresponding script; see [`docs/benchmarking.md`](docs/benchmarking.md) for
full methodology and how to reproduce or extend them.

## 9. Security model

**What this project protects, when used as designed:**

- Confidentiality of file contents, via AES-256-GCM under a key derived from
  a hybrid (classical + PQC) key establishment.
- Integrity/authenticity of encrypted packages, via AES-GCM's authentication
  tag over both ciphertext and associated metadata, plus an independent
  hybrid (ML-DSA + Ed25519) signature layer.
- Forward-looking key-establishment secrecy: the hybrid session key stays
  secret as long as **at least one** of X25519 or ML-KEM remains unbroken.
- Explicit algorithm/version identifiers in every serialized package, so a
  decryptor validates compatibility before trusting anything, and so future
  algorithm upgrades don't silently break or misinterpret older packages.

**What it does not protect, and does not claim to:**

- A compromised endpoint (malware with access to plaintext or key material
  in memory) — no cryptography operating on that endpoint can help.
- Metadata about *that* a file was encrypted, its size, or communication
  timing/pattern (no traffic analysis resistance).
- Formal, machine-checked proof of the hybrid composition's security — see
  [`docs/security_analysis.md`](docs/security_analysis.md) for exactly what
  is and isn't claimed about combining two independent algorithms.
- Side-channel resistance: the underlying `kyber-py`/`dilithium-py`
  implementations are educational, pure-Python, and explicitly **not**
  constant-time or side-channel-hardened.

## 10. Limitations

**This project has not been independently security-audited and must not be
treated as production cryptographic infrastructure.** Concretely:

- `kyber-py` and `dilithium-py` are educational, pure-Python implementations
  of FIPS 203/204, written for clarity rather than deployment. They make no
  constant-time or side-channel-resistance guarantees.
- Key storage (`pqcrypto.keys.key_storage`) is plain local files, not an HSM,
  secure enclave, or OS keystore; without an explicit passphrase, secret keys
  are stored in **plaintext** on disk.
- File encryption encrypts the whole plaintext as a single AES-GCM
  operation, not a chunked/streaming AEAD — see `file_encryptor.py`'s module
  docstring for exactly what that does and doesn't cover for very large files.
- No formal protocol verification, no third-party cryptographic review, and
  no claim of FIPS certification for this project's own code (only the
  underlying algorithms are FIPS-standardized; this implementation of them
  is not a validated FIPS module).

If you need production-grade PQC, use a vetted, audited implementation (e.g.
liboqs with hardware-backed key storage) integrated by people with
cryptographic-engineering review processes in place — not this repository.

## 11. Threat model (summary)

Full threat model: [`docs/threat_model.md`](docs/threat_model.md).

- **Assets**: plaintext files, private/secret keys, shared secrets,
  signatures, encrypted packages, and their metadata.
- **Attackers considered**: passive network eavesdroppers, active
  ciphertext/package modification, an attacker with a future large-scale
  quantum computer, and (explicitly out of scope for cryptography to solve)
  a compromised endpoint.
- **Goals**: confidentiality, integrity, authenticity, key confidentiality,
  downgrade resistance, and algorithm agility (the ability to swap
  algorithms later without a format rewrite).
- **Explicit non-goal**: protecting secrets already exposed by a compromised
  endpoint — no cryptographic design can do that.

## 12. Migration guidance

Full guide: [`docs/migration_guide.md`](docs/migration_guide.md). In brief,
organizations considering a move from classical public-key cryptography
toward PQC should: inventory where classical public-key crypto is actually
used, identify long-lived sensitive data exposed to store-now-decrypt-later,
prefer **hybrid** classical+PQC during the transition rather than a
flag-day cutover, benchmark the real size/performance overhead PQC adds to
their specific protocols (message sizes are the more common practical
constraint than raw CPU time), and track evolving standards rather than
treating any single algorithm/parameter-set choice as permanent. This
project's own hybrid designs (`pqcrypto.hybrid.key_exchange`,
`pqcrypto.hybrid.signatures`) are worked examples of that pattern, not a
turnkey migration tool.

## 13. Project structure

See the architecture tree in [section 4](#4-architecture) above, and
[`docs/architecture.md`](docs/architecture.md) for what each module is
responsible for and why the boundaries are drawn where they are.

## 14. Academic value

Working through this codebase (or extending it) exercises:

- The practical difference between a **KEM** (ML-KEM) and a raw
  Diffie-Hellman **key-agreement** primitive (X25519), and why a KEM
  interface generalizes better across algorithm families.
- Why digital signatures and key encapsulation are different primitives
  solving different problems (authenticity vs. secrecy), even though both
  are "public-key cryptography."
- Why bulk data is never encrypted directly with a KEM/PQC primitive, and
  the standard "asymmetric establishes a key, symmetric encrypts the data"
  hybrid pattern used throughout real-world protocols (TLS included).
- Why independently-established secrets need a KDF (HKDF) rather than naive
  concatenation, and what domain separation (`info`/`context` parameters)
  actually buys you.
- The engineering discipline of isolating third-party cryptographic APIs
  behind stable wrapper interfaces, explicit format versioning, and
  fail-loudly validation — independent of which specific algorithms are
  involved.
- How to structure a test suite around a *security contract* (e.g. ML-KEM's
  implicit rejection: a tampered ciphertext must not raise, only silently
  diverge) rather than around implementation details.

This project does not claim to have been formally, independently
security-audited; see [Limitations](#limitations) above and
[`docs/security_analysis.md`](docs/security_analysis.md) for the complete,
honest accounting of what has and hasn't been verified.
