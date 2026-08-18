# Benchmarking Methodology

This document explains how `benchmarks/*.py` measure performance, why each
methodological choice was made, and how to reproduce or extend the results.
See [`README.md#8-benchmarking`](../README.md#8-benchmarking) for the quick
command reference.

## What is measured, and why

| Script | Measures | Why it matters |
|---|---|---|
| `benchmark_kem.py` | ML-KEM-512/768/1024 keygen, encapsulate, decapsulate | How PQC key establishment cost scales with security level. |
| `benchmark_signatures.py` | ML-DSA-44/65/87 and Ed25519 keygen, sign, verify | How PQC signing cost compares across security levels, and against a classical baseline, using an identical message. |
| `benchmark_encryption.py` | AES-256-GCM encrypt/decrypt at 1 KiB–100 MiB | Whether the symmetric layer (unaffected by the PQC transition) stays fast regardless of file size, and what AES-GCM's fixed per-package overhead is. |
| `benchmark_classical.py` | X25519 vs. ML-KEM-768; Ed25519 vs. ML-DSA-65, side by side | Direct classical-vs-PQC comparison using one consistent methodology, plus size-overhead ratios. |

Every script imports this project's own wrapper classes (`MLKEM`, `MLDSA`,
`ClassicalKEM`, `ClassicalSignature`, `pqcrypto.encryption.aes`) — never the
third-party backends directly — so what's measured is exactly what the rest
of the project actually calls.

## Warm-up

Every timed series runs a small number of **untimed** warm-up iterations
first (`benchmarks/_bench_common.py`'s `DEFAULT_WARMUP_ITERATIONS = 3` by
default, tuned per series where a different count makes sense — see each
script). This absorbs one-time costs — module import machinery already
running, CPU frequency scaling ramping up, OS page/disk caching — that would
otherwise bias only the *first* sample and skew small-iteration-count series
disproportionately.

Exception: when a series is pre-seeded with an exact number of independently
prepared inputs (e.g. `benchmark_kem.py`'s decapsulation series, which
consumes one pre-generated ciphertext per sample from a fixed-size list),
warm-up is set to `0` — running warm-up iterations would consume samples
meant for the timed measurement and leave too few (or none) for the
remainder, since the input list's length matches the intended iteration
count exactly.

## Repetitions and statistics

Each operation is repeated many times (typically 30–200 depending on the
operation's cost — see each script's `*_ITERATIONS` constants) and reported
as:

- **mean** — arithmetic average, most useful for aggregate/throughput
  comparisons.
- **median** — the middle sample, more robust to occasional outliers (e.g. a
  GC pause or OS scheduling hiccup) than the mean.
- **standard deviation** — how much individual samples varied; a high stdev
  relative to the mean is a signal the environment was noisy during that
  run, not necessarily that the algorithm itself is inconsistent.
- **min/max** — the observed range.
- **ops/second** — `1 / mean`, the throughput-oriented view most useful for
  "how many of these could this machine do per second" questions.

No benchmark in this project asserts or hard-codes an "expected" timing
value anywhere — `_bench_common.py` only measures and reports.

## Independence between samples

- **Key generation** is timed as `iterations` fully independent keypair
  generations — never "generate once, then time re-reading the same
  result."
- **Encapsulation/signing** is timed against ONE fixed keypair (matching
  real usage: many independent operations against one long-lived key), with
  each individual sample still performing a genuinely fresh operation
  (fresh randomness where the algorithm uses it).
- **Decapsulation/verification** is timed against **pre-computed** valid
  ciphertexts/signatures, generated *before* the timed region starts, so
  that generating the input never leaks into the decrypt/verify timing.

## Hardware and software dependence

**These numbers describe one specific run, on one specific machine, with one
specific set of installed library versions — nothing more universal than
that.** Every JSON result file under `data/benchmark_results/` includes an
`"environment"` section recording: Python version and implementation,
platform string, processor/machine architecture, and the installed version
of `cryptography`, `kyber_py`, and `dilithium_py`. Re-running the same
script on different hardware, a different OS, or different library versions
will produce different absolute numbers; relative comparisons *within* one
run (e.g. "ML-KEM-1024 vs. ML-KEM-512 on this run") are more meaningful than
comparing absolute numbers across different runs or different machines.

## Message/file, key, signature, and ciphertext sizes

Sizes reported alongside timing (`public_key_size_bytes`,
`secret_key_size_bytes`, `ciphertext_size_bytes`/`signature_size_bytes`,
`shared_secret_size_bytes`) come directly from each wrapper's own advertised
size properties (`MLKEM.public_key_size`, etc.) — the same properties
`tests/test_ml_kem.py::test_component_sizes_match_advertised` and its ML-DSA
counterpart verify against real generated artifacts, not hard-coded
constants disconnected from the implementation.

`benchmark_encryption.py` additionally reports
`throughput_mib_per_second` (derived from the measured mean time — not
independently measured) and the AEAD's fixed per-package overhead
(`NONCE_SIZE + TAG_SIZE` = 28 bytes, independent of plaintext size).

## Reproducing measurements

```bash
pip install -r requirements-dev.txt
python benchmarks/benchmark_kem.py
python benchmarks/benchmark_signatures.py
python benchmarks/benchmark_encryption.py
python benchmarks/benchmark_classical.py
```

Each run overwrites `data/benchmark_results/<script-name>.json` with a fresh
result (including a new `generated_at` timestamp) — there is no
accumulation or averaging across separate `python benchmarks/...` runs. If
you want to compare runs over time, copy the JSON files out (or rename them)
between invocations, or add versioning around them outside this project's
own scope.

## Classical vs. PQC vs. Hybrid, at a glance

| | Key establishment cost | Artifact size | Quantum-safe? |
|---|---|---|---|
| **Classical** (X25519 / Ed25519) | Lowest (see `benchmark_classical.py`) | Smallest (32/64 bytes) | No |
| **PQC** (ML-KEM / ML-DSA) | Higher, grows with security level | Much larger (see the size-overhead ratios `benchmark_classical.py` prints) | Believed yes (see `cryptography.md`, `security_analysis.md`) |
| **Hybrid** (this project's default posture) | Sum of both components' cost (see `hybrid/key_exchange.py`/`hybrid/signatures.py`, not separately re-benchmarked here since it's the composition of the two rows above) | Sum of both components' sizes | Yes, as long as at least one component holds |

This project does not fabricate a "hybrid" row of numbers separate from
combining the classical and PQC rows above — the hybrid cost is
mechanically the sum of its two components' costs (one classical operation
plus one PQC operation plus one HKDF call, per `hybrid/kdf.py`'s negligible
overhead relative to either KEM/signature operation).
