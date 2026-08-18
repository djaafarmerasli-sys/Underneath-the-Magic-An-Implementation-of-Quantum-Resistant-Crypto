# Architecture

## 1. System overview

`pqcrypto` is organized in five layers. Each layer depends only on the
layer(s) below it — there are no upward or sideways dependencies back into
`hybrid/` from `kem/`, for instance, and no module outside `kem/`/`signatures/`
talks to a third-party cryptographic library directly.

```mermaid
flowchart TB
    subgraph L5["Application layer"]
        FE[file_encryptor.py]
        FD[file_decryptor.py]
        KM[key_manager.py]
    end

    subgraph L4["Hybrid layer"]
        KX[key_exchange.py]
        HS[hybrid/signatures.py]
        KDF[kdf.py]
    end

    subgraph L3["Algorithm wrappers"]
        MLKEM[kem/ml_kem.py]
        CKEM[kem/classical_kem.py]
        MLDSA[signatures/ml_dsa.py]
        CSIG[signatures/classical_signature.py]
        AES[encryption/aes.py]
    end

    subgraph L2["Support"]
        KS[keys/key_storage.py]
        SER[utils/serialization.py]
        RND[utils/randomness.py]
    end

    subgraph L1["Third-party libraries"]
        KYBER[kyber-py]
        DIL[dilithium-py]
        PYCA[cryptography]
    end

    FE --> KX
    FE --> AES
    FD --> KX
    FD --> AES
    KM --> MLKEM
    KM --> MLDSA
    KM --> CKEM
    KM --> CSIG
    KM --> KS

    KX --> MLKEM
    KX --> CKEM
    KX --> KDF
    HS --> MLDSA
    HS --> CSIG

    MLKEM --> KYBER
    MLDSA --> DIL
    CKEM --> PYCA
    CSIG --> PYCA
    AES --> PYCA
    KDF --> PYCA
    KS --> AES
    KS --> RND
    KS --> SER
    FE --> KDF
    FD --> KDF
    FE --> SER
    FD --> SER
```

## 2. Component responsibilities

| Module | Responsibility |
|---|---|
| `kem/ml_kem.py` | Thin wrapper around `kyber-py`; the ONLY place ML-KEM's third-party API is touched. |
| `kem/classical_kem.py` | X25519 wrapped in the same `generate_keypair`/`encapsulate`/`decapsulate` shape as `MLKEM`, via a DHKEM construction. |
| `signatures/ml_dsa.py` | Thin wrapper around `dilithium-py`; the ONLY place ML-DSA's third-party API is touched. |
| `signatures/classical_signature.py` | Ed25519, matching `MLDSA`'s method shape. |
| `hybrid/kdf.py` | HKDF-SHA256 combiner: turns one or more independently-established secrets into uniformly-random output key bytes, with mandatory domain separation. |
| `hybrid/key_exchange.py` | Combines `ClassicalKEM` + `MLKEM` via `kdf.py` into one session key; defines `HybridPublicKey`/`HybridSecretKey`/`HybridCiphertext`. |
| `hybrid/signatures.py` | Combines `MLDSA` + `ClassicalSignature`; verification policy is AND (both must verify). |
| `encryption/aes.py` | AES-256-GCM only. The sole place plaintext bytes are actually encrypted. |
| `encryption/file_encryptor.py` / `file_decryptor.py` | Wires hybrid key establishment → KDF → AES-GCM into one file-level operation, and its exact inverse. |
| `keys/key_storage.py` | Filesystem persistence: public/secret/metadata kept in separate subdirectories; optional passphrase-based encryption at rest. |
| `keys/key_manager.py` | Key lifecycle on top of `key_storage.py`: IDs, metadata, generation, rotation, deletion — never exposes key bytes through a metadata call. |
| `utils/serialization.py` | JSON envelope helpers: base64 for binary fields, required-field validation, deterministic encoding. |
| `utils/randomness.py` | `secrets`-backed random bytes for the project's OWN supporting code (salts, key IDs) — never used to seed ML-KEM/ML-DSA, which manage their own randomness per their FIPS specs. |

## 3. Dependency boundaries

```text
src/pqcrypto/encryption/file_encryptor.py, file_decryptor.py
        depends on: hybrid/key_exchange.py, hybrid/kdf.py, encryption/aes.py, utils/serialization.py
        MUST NOT depend on: kyber_py / dilithium_py / cryptography directly

src/pqcrypto/hybrid/*.py
        depends on: kem/*.py, signatures/*.py, (kdf.py depends on `cryptography`'s HKDF only)
        MUST NOT depend on: kyber_py / dilithium_py directly

src/pqcrypto/kem/ml_kem.py            <-> kyber_py         (isolated here only)
src/pqcrypto/signatures/ml_dsa.py     <-> dilithium_py      (isolated here only)
src/pqcrypto/kem/classical_kem.py,
src/pqcrypto/signatures/classical_signature.py,
src/pqcrypto/encryption/aes.py,
src/pqcrypto/hybrid/kdf.py            <-> cryptography (pyca)   (isolated to these files)
```

If `kyber-py` or `dilithium-py`'s API changes shape, only `ml_kem.py` /
`ml_dsa.py` need to change — every other module in the project depends on
`MLKEM/MLDSA`'s stable method signatures, never on the backend's own names.

## 4. Why the layers are separated the way they are

**Why ML-KEM is separated from AES.** ML-KEM is a KEM: it produces a
32-byte shared secret, not general-purpose ciphertext for arbitrary-length
plaintext. Using it to "encrypt" a file directly would be both wrong (it has
no such operation) and, even approximated, catastrophically inefficient —
lattice-based ciphertexts are hundreds to thousands of bytes to carry 32
bytes of payload. The standard, correct pattern — used here and in every
serious protocol (TLS 1.3's PQC hybrid modes included) — is: asymmetric
primitive establishes a *key*, symmetric primitive (AES-256-GCM) encrypts
the *data*.

**Why ML-DSA is separated from encryption.** Signing and encrypting solve
different problems (authenticity vs. confidentiality) and have independent
failure modes; keeping `hybrid/signatures.py` and `encryption/file_*.py` as
separate call sites means a caller must explicitly choose to add a signature
layer rather than getting one bundled invisibly into "encryption," and means
either can be tested, benchmarked, and reasoned about independently.

**Why the KDF is its own module.** `hybrid/kdf.py` is imported by BOTH
`hybrid/key_exchange.py` (deriving the hybrid session key) and
`encryption/file_encryptor.py`/`file_decryptor.py` (deriving the
file-specific AES key from that session key, with a *different*
domain-separation context — see `FILE_ENCRYPTION_KDF_CONTEXT` vs.
`HYBRID_KEX_CONTEXT`). Centralizing the HKDF call means every derivation in
the project goes through the same reviewed construction and the same
input-length validation, instead of each call site re-implementing "hash
some secrets together."

**Why third-party crypto APIs are isolated behind wrappers.** `kyber-py`
and `dilithium-py` are pre-1.0, educational implementations that ship one
object per parameter set with their own (non-standardized-across-libraries)
method names. Wrapping them behind `MLKEM`/`MLDSA` means: (1) the rest of
the project has one stable interface to depend on regardless of backend
churn, (2) input validation and error types are consistent everywhere, and
(3) swapping to a different backend (e.g. a future `liboqs`-based
implementation) touches exactly one file per algorithm.

**Why encrypted files carry explicit algorithm/version metadata.**
`EncryptedFilePackage` includes `version`, `kdf_algorithm`, `aead_algorithm`,
`classical_algorithm`, and `ml_kem_security_level` as plain (non-secret)
fields, and binds them into the AES-GCM associated data so they can't be
swapped undetected. This is what makes **algorithm agility** possible: a
future version of this project can add a new AEAD or PQC parameter set and
still correctly reject (rather than silently mis-decrypt) a package produced
under a different, unsupported combination — see
`file_decryptor.py`'s version/algorithm checks, which run *before* any key
recovery is attempted.

## 5. Data flow diagrams

### 5.1 Hybrid key-exchange flow

```mermaid
sequenceDiagram
    participant Sender
    participant Recipient

    Recipient->>Recipient: generate_keypair() -> (X25519 pk/sk, ML-KEM pk/sk)
    Recipient-->>Sender: HybridPublicKey (both public halves)

    Sender->>Sender: initiate(recipient_public_key)
    Note over Sender: X25519 DHKEM encapsulate + ML-KEM encapsulate,<br/>then HKDF(classical_secret || pq_secret) -> session_key
    Sender-->>Recipient: HybridCiphertext (both ciphertext halves + algorithm IDs + version)

    Recipient->>Recipient: respond(secret_key, ciphertext)
    Note over Recipient: validate version + algorithm IDs,<br/>X25519 decapsulate + ML-KEM decapsulate,<br/>same HKDF -> session_key

    Note over Sender,Recipient: Both sides now hold the identical 32-byte session_key
```

### 5.2 File encryption flow

```mermaid
flowchart LR
    A[plaintext bytes] --> B["hybrid key-exchange.initiate()\n(fresh handshake per call)"]
    B --> C[session_key]
    C --> D["KDF (file-specific context)"]
    D --> E[AES-256 file_key]
    A --> F["AES-256-GCM encrypt\n(fresh nonce)"]
    E --> F
    G[package metadata\nversion + algorithm IDs] -->|associated data| F
    F --> H[EncryptedFilePackage]
    B --> G
```

### 5.3 File decryption flow

```mermaid
flowchart LR
    H[EncryptedFilePackage] --> V{"version +\nalgorithm IDs\nsupported?"}
    V -- no --> R1[raise FileDecryptorError]
    V -- yes --> K["hybrid key-exchange.respond()\nwith recipient secret_key"]
    K -- HybridKeyExchangeError --> R2[raise FileDecryptorError]
    K -- session_key --> D["KDF (same file-specific context)"]
    D --> E[AES-256 file_key]
    H -->|nonce, ciphertext,\nassociated data| G["AES-256-GCM decrypt\n+ authenticate"]
    E --> G
    G -- AuthenticationError --> R3[raise FileDecryptorError]
    G -- success --> P[plaintext -- returned ONLY here]
```

### 5.4 Signing flow

```mermaid
flowchart LR
    M[message bytes] --> S1[ML-DSA.sign]
    M --> S2[Ed25519.sign]
    S1 --> H[HybridSignature\nboth signatures + algorithm IDs + version]
    S2 --> H
    H --> V1[ML-DSA.verify]
    H --> V2[Ed25519.verify]
    V1 --> AND{AND}
    V2 --> AND
    AND -- both true --> OK[verified]
    AND -- either false --> NO[rejected]
```

### 5.5 Key-management flow

```mermaid
flowchart LR
    G["KeyManager.generate_*_keypair()"] --> ALG["MLKEM / MLDSA / ClassicalKEM /\nClassicalSignature .generate_keypair()"]
    ALG --> PK[public_key bytes]
    ALG --> SK[secret_key bytes]
    PK --> ST1["KeyStorage.save_public_key()\n(plaintext -- public keys need no confidentiality)"]
    SK --> ST2["KeyStorage.save_secret_key()\n(plaintext, OR scrypt+AES-256-GCM if passphrase given)"]
    G --> META[KeyRecord: key_id, algorithm,\nsecurity_level, created_at]
    META --> ST3["KeyStorage.save_metadata()\n(NEVER contains key bytes)"]
```

### 5.6 Serialization flow

`utils/serialization.py` provides one canonical envelope used by both
`keys/key_storage.py` (key metadata) and `encryption/file_encryptor.py`
(`EncryptedFilePackage`): a JSON object with sorted, deterministic key
ordering, binary fields base64-encoded, and caller-declared `required_fields`
checked on load. Neither module invents its own binary layout.

### 5.7 Benchmark flow

Each `benchmarks/benchmark_*.py` script imports the project's own wrapper
classes (never the third-party library directly), runs warm-up iterations,
then timed iterations via the shared `benchmarks/_bench_common.py` helper,
and writes both a console table and a JSON file under
`data/benchmark_results/`. See [`benchmarking.md`](benchmarking.md) for full
methodology.

## 6. Trust boundaries

```text
                    ┌─────────────────────────────┐
                    │  Untrusted / adversarial     │
                    │  (network, disk, other party)│
                    └──────────────┬───────────────┘
                                   │
      EncryptedFilePackage bytes, HybridCiphertext bytes,
      HybridSignature bytes, public keys -- ALL treated as
      attacker-controlled until validated
                                   │
                                   ▼
      ┌────────────────────────────────────────────────────┐
      │  pqcrypto validation boundary                        │
      │  - type checks (TypeError for wrong Python type)      │
      │  - length checks against the declared algorithm       │
      │  - version/algorithm-identifier checks                │
      │  - AEAD authentication (AES-GCM tag verification)     │
      │  - signature verification (ML-DSA AND classical)      │
      └──────────────────────┬───────────────────────────────┘
                              │  only data that passed EVERY check
                              ▼
                    ┌─────────────────────────────┐
                    │  Trusted: plaintext returned  │
                    │  to the caller                │
                    └─────────────────────────────┘
```

Private/secret key material (`HybridSecretKey`, raw ML-KEM/ML-DSA/X25519/
Ed25519 secret keys) is trusted local state, supplied by the caller — this
project never receives secret keys over an untrusted channel and never
transmits them. The one place secret key bytes touch disk
(`keys/key_storage.py`) is documented as plaintext-by-default with an
explicit opt-in passphrase-encryption path; see that module's docstring and
[`security_analysis.md`](security_analysis.md) for the full caveat.
