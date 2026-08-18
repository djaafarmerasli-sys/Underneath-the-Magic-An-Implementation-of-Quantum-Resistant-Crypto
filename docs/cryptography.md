# Cryptographic Background

This document is the educational companion to the code: it explains the
concepts behind every primitive `pqcrypto` uses, at a level that assumes
programming background but not a cryptography degree. For how these pieces
are wired together in this specific codebase, see
[`architecture.md`](architecture.md); for what security properties are and
aren't actually claimed, see [`security_analysis.md`](security_analysis.md).

Throughout: **"believed secure against quantum adversaries"** is a
statement about the current state of cryptanalysis — no known efficient
attack, quantum or classical, is public. It is not the same claim as
**"mathematically proven impossible to break"** — no widely-used public-key
cryptosystem (classical or post-quantum) has that kind of unconditional
proof; security rests on decades of attempted cryptanalysis failing, not on
a proof that no attack can exist.

## Classical cryptography

### RSA

RSA's security rests on the difficulty of factoring the product of two large
prime numbers. Given `n = p * q` for large primes `p, q`, recovering `p` and
`q` from `n` alone is believed to be computationally infeasible classically
— but Shor's algorithm factors `n` in polynomial time on a large enough
quantum computer, which would let an attacker recover the private key from
the public key directly. This project does not use RSA (its keys/ciphertexts
are also large and awkward compared to elliptic-curve or lattice
alternatives at comparable security levels), but it's the algorithm most PQC
discussions use as the canonical example of what quantum computers threaten.

### Elliptic-curve cryptography (ECC)

Instead of factoring, ECC's security rests on the **elliptic-curve discrete
logarithm problem**: given points `P` and `Q = k * P` on an elliptic curve,
recovering the scalar `k` is believed classically hard. This project uses
two ECC primitives as its classical baseline:

- **X25519** (Diffie-Hellman over Curve25519) for key agreement —
  `pqcrypto.kem.classical_kem`.
- **Ed25519** (EdDSA over the same curve family) for signatures —
  `pqcrypto.signatures.classical_signature`.

Both are modern, widely deployed, and constant-time in the `cryptography`
(pyca) library's implementation. Both are also **fully broken by Shor's
algorithm** on a sufficiently large quantum computer, in exactly the same
way as RSA — the discrete-log problem, whether over integers or elliptic
curves, is Shor's target.

### Classical signatures

A signature scheme lets a secret-key holder produce, for a message, a value
that anyone with the matching public key can verify — but that nobody
without the secret key can forge. Ed25519 is deterministic (no per-signature
randomness required from the caller), which sidesteps an entire historical
class of real-world key-recovery bugs in classical ECDSA caused by
nonce reuse or weak randomness.

### AES

The Advanced Encryption Standard (AES) is a symmetric block cipher: the same
secret key encrypts and decrypts. Its security does not rest on
factoring or discrete logarithms at all — it rests on the cipher's
resistance to differential/linear cryptanalysis over its round structure,
an entirely different kind of hardness than public-key cryptography's.
This is why AES survives the transition to a post-quantum world essentially
unchanged (see below): Shor's algorithm has nothing to attack here.

## The quantum threat

### Quantum computing, briefly

A quantum computer performs computation using quantum bits (qubits), which
can exist in superpositions and be entangled, enabling certain algorithms to
explore a problem's structure in ways no classical algorithm can efficiently
replicate. This is not "a faster classical computer" — most computational
problems get no meaningful quantum speedup at all. The problems that
*do* get a dramatic speedup happen to include exactly the ones classical
public-key cryptography is built on.

### Shor's algorithm

Peter Shor's 1994 algorithm solves integer factorization and the discrete
logarithm problem (including the elliptic-curve variant) in polynomial time
on a quantum computer, versus the best known classical algorithms' sub
exponential/exponential time. A quantum computer large and stable enough to
run Shor's algorithm against real-world key sizes (thousands of stable
logical qubits, far beyond anything built as of this writing) would let an
attacker recover RSA, DH, ECDH, and ECDSA/Ed25519/X25519 private keys from
public keys directly.

### Grover's algorithm

Lov Grover's 1996 algorithm gives a quadratic speedup for unstructured
search problems — including brute-forcing a symmetric key. Against AES-256,
this reduces the *effective* security level from 2^256 to roughly 2^128
operations — still astronomically infeasible. This is the entire reason
symmetric cryptography does not need a "post-quantum AES": doubling the key
size (which AES-256 already provides relative to AES-128) absorbs Grover's
speedup with room to spare. Hash functions face the same quadratic-only
impact via Grover's algorithm applied to preimage search.

### Why public-key and symmetric cryptography are affected so differently

Shor's algorithm is *structural*: it exploits the specific algebraic
structure (periodicity) underlying factoring and discrete logarithms.
Grover's algorithm is *generic*: it works against any unstructured search
problem, symmetric ciphers included, but only quadratically. Post-quantum
cryptography research therefore focuses almost entirely on replacing the
*public-key* layer — key exchange and signatures — with problems that don't
have Shor-exploitable structure, while leaving symmetric primitives like AES
essentially as they are (at most, doubling key length as a margin).

## ML-KEM

### KEM concept

A **Key Encapsulation Mechanism** solves "how do two parties who've never
met agree on a shared secret over a public channel," but does so through a
different interface than raw Diffie-Hellman:

```text
generate_keypair()                    -> (public_key, secret_key)
encapsulate(public_key)               -> (ciphertext, shared_secret)   # sender
decapsulate(secret_key, ciphertext)   -> shared_secret                  # recipient
```

A KEM is not general-purpose encryption — there is no "plaintext" argument
anywhere in this interface. It does exactly one job: mint a fresh random
shared secret and seal it into a ciphertext that only the matching secret
key can open.

### Encapsulation / decapsulation

**Encapsulation** (sender side) takes the recipient's public key and
produces two things at once: a brand-new random shared secret, and a
ciphertext that carries it. **Decapsulation** (recipient side) takes that
ciphertext and the matching secret key, and recovers the identical shared
secret. Both operations are single function calls — there is no multi-round
handshake at the KEM level itself (a real protocol built on a KEM, like TLS,
adds its own framing around this).

### Module-LWE

ML-KEM's security rests on the **Module Learning-With-Errors** problem: given
many linear equations over a structured lattice, each deliberately corrupted
with a small amount of random "noise," recover the hidden secret vector.
Without the noise this would be a straightforward system of linear
equations (easy); with it, and over the module-lattice structure ML-KEM
uses, the best known algorithms — classical or quantum — for recovering the
secret are believed to require infeasible amounts of computation at the
standardized parameter sizes. This is a *different* mathematical structure
than factoring or discrete logarithms, so Shor's algorithm's techniques do
not carry over.

### Parameter sets and shared secrets

FIPS 203 standardizes three parameter sets, trading key/ciphertext size for
security margin:

| Level | NIST category | ~symmetric equivalent | Public key | Secret key | Ciphertext |
|---|---|---|---|---|---|
| ML-KEM-512 | 1 | AES-128 | 800 B | 1632 B | 768 B |
| ML-KEM-768 | 3 | AES-192 | 1184 B | 2400 B | 1088 B |
| ML-KEM-1024 | 5 | AES-256 | 1568 B | 3168 B | 1568 B |

Every level produces a **32-byte (256-bit) shared secret**, matching what
AES-256 needs. This project defaults to ML-KEM-768, matching NIST's general
recommendation and what protocols like TLS 1.3's PQC hybrid modes have
adopted.

### Ciphertexts, and why they're "big"

ML-KEM ciphertexts (768–1568 bytes) are far larger than an X25519 public key
(32 bytes) for the same conceptual job ("carry enough information to
establish a 32-byte secret"). This is the direct, unavoidable cost of moving
from elliptic-curve points to lattice-based structures with noise built in
— see `benchmarks/benchmark_classical.py` for this project's own measured
size ratios between the two.

## ML-DSA

### Digital signatures, signing, verification

Same three-operation shape as classical signatures:

```text
generate_keypair()                          -> (public_key, secret_key)
sign(message, secret_key)                   -> signature
verify(message, signature, public_key)      -> bool
```

A valid signature proves the secret-key holder produced it for *this exact
message* — changing even one byte of the message must invalidate the
signature, and nobody without the secret key should be able to produce a
signature that verifies.

### Lattice-based security

Like ML-KEM, ML-DSA's hardness rests on Module-LWE (plus a related "Short
Integer Solution"-flavored problem and a **Fiat-Shamir with aborts**
construction that turns the underlying lattice problem into a signing
scheme). "Fiat-Shamir with aborts" means the signing algorithm sometimes
restarts internally (rejection sampling) to keep the output's statistical
distribution from leaking information about the secret key — this is
handled entirely inside `dilithium-py`; this project's wrapper never
observes or needs to know about individual signing attempts.

### Parameter sets

FIPS 204 standardizes three parameter sets:

| Level | NIST category | ~symmetric equivalent | Public key | Secret key | Signature |
|---|---|---|---|---|---|
| ML-DSA-44 | 2 | AES-128 | 1312 B | 2560 B | 2420 B |
| ML-DSA-65 | 3 | AES-192 | 1952 B | 4032 B | 3309 B |
| ML-DSA-87 | 5 | AES-256 | 2592 B | 4896 B | 4627 B |

This project defaults to ML-DSA-65, NIST's general recommendation.

## Hybrid cryptography

**Why combine classical and PQC during migration?** Two independent risks
point in opposite directions right now: (1) PQC algorithms are new —
ML-KEM/ML-DSA were only finalized in 2024, and newer cryptography has
historically had a higher rate of unexpected cryptanalytic breaks simply
from having had less collective scrutiny than 20-plus-year-old classical
algorithms; (2) classical algorithms are the ones a future quantum computer
specifically threatens. A **hybrid** construction — requiring both to hold
for security, e.g. `session_key = KDF(classical_secret || pq_secret)` for
key exchange, or `verify = ML-DSA_valid AND classical_valid` for signatures
— stays secure as long as *at least one* of the two components remains
unbroken, covering both risks simultaneously. See
`pqcrypto.hybrid.key_exchange` and `pqcrypto.hybrid.signatures`.

## KDF

**Why not just concatenate secrets and use them directly?** Two independent
problems: (1) raw Diffie-Hellman output (X25519's shared secret here) is a
curve-point coordinate, not a uniformly random bit string — using it
directly as an AES key reuses structure an attacker could potentially
exploit; (2) combining *two* secrets by simple concatenation gives no formal
guarantee about the combined output's security if one input turns out to be
weak, biased, or adversarially influenced. A **KDF (Key Derivation
Function)** — this project uses **HKDF-SHA256** (RFC 5869) via
`cryptography`'s implementation, exclusively — is a construction
independently designed and analyzed for exactly this "combine keying
material into uniform output key bytes" role. `pqcrypto.hybrid.kdf` never
implements its own hash-and-truncate scheme.

## AES-GCM

**Confidentiality**: AES in Galois/Counter Mode (GCM) encrypts plaintext
into ciphertext of the same length, keyed by a 256-bit key. **Authentication
(AEAD)**: GCM additionally computes a 128-bit authentication tag over the
ciphertext (and any associated data); decryption verifies this tag
*before* returning any plaintext, and fails outright — no "garbage
plaintext," no partial output — if the tag doesn't match. This is why AES-GCM
is used here rather than an unauthenticated mode like CBC: CBC alone gives
no cryptographic signal that a ciphertext was tampered with, which is a
long-documented source of real-world vulnerabilities (padding-oracle
attacks among them).

**Nonce requirements**: GCM's security guarantee collapses completely if the
same (key, nonce) pair is ever used to encrypt two different messages — it
can leak the authentication key entirely, enabling forgery. `pqcrypto`'s
`encrypt()` therefore generates a fresh, cryptographically random 96-bit
nonce on every single call and always returns it bundled with the
ciphertext, so a caller cannot accidentally lose it or reuse a stale one.

**Associated data (AAD)**: data that is authenticated but not encrypted — it
travels alongside the ciphertext in the clear, but decryption fails if it
doesn't match exactly what was supplied at encryption time. This project
uses AAD to bind an `EncryptedFilePackage`'s algorithm/version metadata to
its ciphertext (see `file_encryptor.py`), so that metadata can't be swapped
onto a captured ciphertext undetected.
