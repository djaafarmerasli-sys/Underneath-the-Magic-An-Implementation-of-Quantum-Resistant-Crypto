# Migration Guide: Classical Public-Key Cryptography → Post-Quantum

**This is educational material illustrating migration concepts using this
project's own algorithms (ML-KEM, ML-DSA) as worked examples — it is not
production migration advice for a real organization.** Any real migration
should be led by people with cryptographic-engineering and risk-management
expertise, informed by your organization's actual systems, threat model, and
compliance requirements, none of which this document can know.

There is no single "correct" migration path, and no single algorithm or
parameter-set choice this document (or this project) claims is universally
appropriate — the right choice depends on your specific protocols,
performance constraints, and risk tolerance.

## 1. Cryptographic inventory

Before migrating anything, know what you have. Enumerate every place
classical public-key cryptography is used: TLS termination points, VPNs,
code-signing, document/email signing, SSH, database encryption, internal
service-to-service auth, embedded devices with fixed firmware, third-party
SDKs and libraries you depend on but don't control the internals of.
Cryptographic inventory is frequently the single largest effort in a real
migration — most organizations underestimate how many places
RSA/ECDH/ECDSA is quietly load-bearing.

## 2. Identify long-lived sensitive data

Separate data by how long it needs to stay confidential: a session key
that's discarded in seconds carries essentially no store-now-decrypt-later
risk; a health record, government communication, or trade secret that must
stay confidential for 10-20+ years carries substantial risk *today*, even
though no cryptographically-relevant quantum computer exists yet — the
attacker only needs to capture and store the ciphertext now, and decrypt it
whenever a sufficient quantum computer eventually exists. Prioritize
migration effort toward systems protecting this category first.

## 3. Assess store-now-decrypt-later exposure

For each long-lived-data system identified in step 2, ask: is traffic to
or from this system observable/interceptable today by an adversary who
might have future quantum capability? If yes, the exposure window is
already open — every day of delay adds more historical ciphertext to what a
future quantum computer could retroactively decrypt. This is the strongest
argument for prioritizing PQC migration on confidentiality-critical,
long-lived-data paths over lower-risk ones (e.g. short-lived session
tokens), even before a full inventory is complete.

## 4. Identify protocol dependencies

Public-key cryptography rarely stands alone — it's embedded in protocol
handshakes (TLS), certificate formats (X.509), key-exchange framing, and
often hardware/firmware that assumes fixed key/signature sizes. ML-KEM and
ML-DSA's keys, ciphertexts, and signatures are all substantially larger than
their classical counterparts (see `docs/benchmarking.md`'s size-overhead
table) — protocols and hardware with hard-coded size assumptions
(fixed-size buffers, MTU-sensitive handshakes, constrained embedded
storage) may need explicit redesign, not just an algorithm swap.

## 5. Introduce algorithm agility

Before committing to specific PQC algorithms everywhere, ensure your
formats and protocols *can* express "which algorithm was used" and reject
unsupported combinations safely, rather than assuming one fixed algorithm
forever. This project's own `EncryptedFilePackage`/`HybridCiphertext`/
`HybridSignature` (see `docs/architecture.md`) are small worked examples of
that pattern: explicit `version` and algorithm-identifier fields, validated
before any cryptographic operation proceeds, so a future algorithm addition
doesn't require every consumer to be rewritten simultaneously — an older
decryptor cleanly rejects a package using an algorithm it doesn't know,
rather than misinterpreting it.

## 6. Test PQC implementations

Evaluate correctness (does it produce interoperable, standard-conformant
output — this project's own tests validate against the wrapper's contract,
not against independent third-party test vectors, which is itself a
limitation to be aware of), evaluate maturity/audit history of the specific
library you'd deploy, and evaluate whether it provides the
side-channel/constant-time guarantees your deployment actually needs (see
`docs/security_analysis.md`'s §12 for why this project's own educational
backends explicitly do NOT provide that guarantee, and would not be an
appropriate choice for this step in a real migration).

## 7. Evaluate hybrid approaches

For most organizations migrating today, a **hybrid** design — requiring
both a classical and a post-quantum algorithm to hold for security, as this
project's `hybrid/key_exchange.py` and `hybrid/signatures.py` demonstrate —
is the more conservative choice than a flag-day cutover straight to
PQC-only. It hedges against two distinct risks at once: newer PQC algorithms
having a shorter public cryptanalysis track record, versus classical
algorithms being the ones a future quantum computer specifically threatens.
Many real-world early PQC deployments (e.g. TLS 1.3's hybrid key-exchange
modes) have taken this same hybrid-first approach for the same reason.

## 8. Benchmark performance and message-size overhead

Run realistic benchmarks against your actual protocols and hardware before
committing — see `docs/benchmarking.md` for this project's own methodology.
In practice, **message/artifact size overhead is usually the more binding
practical constraint than raw CPU time**: ML-KEM/ML-DSA keys, ciphertexts,
and signatures are tens of times larger than their classical counterparts
(see the size-overhead ratios `benchmarks/benchmark_classical.py` computes),
which can matter enormously for protocols with tight framing budgets (MTU-
constrained handshakes, constrained embedded devices, high-volume
signature-heavy workloads) even when the CPU cost difference is
individually negligible.

## 9. Update key management

PQC keys are larger and (for lattice-based schemes broadly) often have
different lifecycle/rotation considerations than classical keys. Review
whether existing key-management infrastructure (HSMs, KMS, certificate
authorities) has been updated to support the specific PQC algorithms you're
adopting — this is frequently a longer lead-time item than the cryptographic
code change itself. This project's own `keys/key_manager.py` /
`keys/key_storage.py` are explicitly educational (see
`docs/security_analysis.md`'s §8) and not a model for production
key-management infrastructure.

## 10. Plan certificate/protocol changes

X.509 and other certificate/protocol formats need explicit support for new
algorithm identifiers (and, for hybrid approaches, potentially composite
certificate formats carrying both a classical and a PQC public key/
signature). This is an ecosystem-wide standardization effort (IETF, CA/
Browser Forum, etc.) largely outside any single organization's control —
track the relevant standards bodies' timelines rather than assuming a
format exists that may still be in draft.

## 11. Monitor evolving standards

FIPS 203/204 were only finalized in 2024; the broader PQC standardization
effort (additional signature schemes, KEMs from different mathematical
families for diversification) continues. Treat any specific algorithm or
parameter-set choice — including this project's ML-KEM-768/ML-DSA-65
defaults — as a snapshot of current guidance, not a permanent decision;
building in algorithm agility (step 5) is what makes revisiting that choice
later tractable rather than another full migration project.

## 12. Maintain rollback/transition strategies without creating insecure downgrades

A migration needs a rollback path for operational safety, but a rollback
path is also exactly the shape of a downgrade-attack surface if implemented
carelessly (an attacker forcing a "fallback" to a weaker classical-only
mode). If you support a transition period where both old and new algorithms
are accepted, ensure that acceptance is a deliberate, explicit,
server/policy-controlled decision — never an automatic silent fallback
triggered by client-supplied input. This project's own hybrid designs avoid
one particular version of this problem: `HybridKeyExchange.respond()` and
`HybridSigner.verify()` never silently fall back to validating only the
classical or only the PQ component if the other is missing or fails — both
are explicitly required, with no code path that treats "one component
absent" as "use whichever one is present" (see `docs/threat_model.md`'s
downgrade-attack discussion).
