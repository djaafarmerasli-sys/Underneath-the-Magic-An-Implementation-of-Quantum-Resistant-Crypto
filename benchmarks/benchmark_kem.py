"""
benchmark_kem.py -- reproducible ML-KEM performance benchmark
===================================================================

Run with:   python benchmarks/benchmark_kem.py

Benchmarks key generation, encapsulation, and decapsulation for all three
ML-KEM parameter sets (512 / 768 / 1024), reporting timing statistics and
component sizes. Results are printed as a table and written as JSON to
data/benchmark_results/benchmark_kem.json.

METHODOLOGY
-------------
* Key generation is timed as its own independent operation per sample: each
  sample generates a brand-new keypair (never reuses one across "iterations"
  of key generation, which would not be measuring key generation at all).
* Encapsulation is timed against ONE fixed keypair's public key -- this
  matches how ML-KEM is actually used (many senders encapsulate to one
  recipient's long-lived public key), and each sample still performs a real,
  independent encapsulation (fresh randomness each time).
* Decapsulation is timed against ciphertexts produced by that same fixed
  keypair, one fresh ciphertext per decapsulation sample, so decapsulation
  is never timed against a "warm" cached result.
* All operations run several warm-up iterations before timing begins.

These numbers describe THIS run, on THIS machine, with THESE installed
library versions -- see the "environment" section of the JSON output. Do
not treat them as universal.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bench_common import TimingStats, print_table, time_operation, write_results

from pqcrypto.kem.ml_kem import MLKEM

SECURITY_LEVELS = [512, 768, 1024]
KEYGEN_ITERATIONS = 50
ENCAPS_ITERATIONS = 100
DECAPS_ITERATIONS = 100


def benchmark_level(security_level: int) -> list[TimingStats]:
    kem = MLKEM(security_level)
    label = f"ML-KEM-{security_level}"
    results: list[TimingStats] = []

    size_extra = {
        "public_key_size_bytes": kem.public_key_size,
        "secret_key_size_bytes": kem.secret_key_size,
        "ciphertext_size_bytes": kem.ciphertext_size,
        "shared_secret_size_bytes": kem.shared_secret_size,
    }

    results.append(
        time_operation(
            f"{label}.generate_keypair",
            lambda: kem.generate_keypair(),
            iterations=KEYGEN_ITERATIONS,
            extra=size_extra,
        )
    )

    # Encapsulation is benchmarked against one fixed recipient public key,
    # matching real usage (many independent encapsulations to one recipient).
    fixed_public_key, fixed_secret_key = kem.generate_keypair()
    results.append(
        time_operation(
            f"{label}.encapsulate",
            lambda: kem.encapsulate(fixed_public_key),
            iterations=ENCAPS_ITERATIONS,
            extra=size_extra,
        )
    )

    # Decapsulation needs a fresh ciphertext per sample; generating it is
    # excluded from the timed region by building the list up front.
    ciphertexts = [kem.encapsulate(fixed_public_key)[0] for _ in range(DECAPS_ITERATIONS)]
    ciphertext_iter = iter(ciphertexts)
    results.append(
        time_operation(
            f"{label}.decapsulate",
            lambda: kem.decapsulate(fixed_secret_key, next(ciphertext_iter)),
            iterations=DECAPS_ITERATIONS,
            warmup_iterations=0,  # warm-up would consume samples meant for timing
            extra=size_extra,
        )
    )

    return results


def main() -> None:
    all_results: list[TimingStats] = []
    for level in SECURITY_LEVELS:
        all_results.extend(benchmark_level(level))

    print_table(all_results)
    output_path = write_results("benchmark_kem", all_results)
    print(f"\nResults written to: {output_path}")


if __name__ == "__main__":
    main()
