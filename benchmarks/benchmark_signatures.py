"""
benchmark_signatures.py -- ML-DSA and classical signature benchmark
=========================================================================

Run with:   python benchmarks/benchmark_signatures.py

Benchmarks key generation, signing, and verification for all three ML-DSA
parameter sets (44 / 65 / 87) and for the project's classical baseline
(Ed25519 -- see pqcrypto.signatures.classical_signature), using the SAME
fixed message for every algorithm so signing/verification timings are
comparable across algorithms rather than confounded by different inputs.

Results are printed as a table and written as JSON to
data/benchmark_results/benchmark_signatures.json.

METHODOLOGY
-------------
* Key generation: one independent, freshly-timed keypair per sample.
* Signing: timed against one fixed keypair, one fresh signature per sample.
* Verification: timed against pre-computed, valid signatures (computing the
  signature is excluded from the timed region), one per sample.
* Warm-up iterations run before every timed series.

These numbers describe THIS run, on THIS machine, with THESE installed
library versions -- not a universal performance claim. See the JSON output's
"environment" section.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bench_common import TimingStats, print_table, time_operation, write_results

from pqcrypto.signatures.classical_signature import ClassicalSignature
from pqcrypto.signatures.ml_dsa import MLDSA

ML_DSA_SECURITY_LEVELS = [44, 65, 87]
MESSAGE = b"The quick brown fox jumps over the lazy dog." * 10  # fixed for every algorithm

KEYGEN_ITERATIONS = 30
SIGN_ITERATIONS = 50
VERIFY_ITERATIONS = 50


def _benchmark_algorithm(label: str, alg, size_extra: dict) -> list[TimingStats]:
    results: list[TimingStats] = []
    extra = {**size_extra, "message_size_bytes": len(MESSAGE)}

    results.append(
        time_operation(
            f"{label}.generate_keypair",
            lambda: alg.generate_keypair(),
            iterations=KEYGEN_ITERATIONS,
            extra=extra,
        )
    )

    public_key, secret_key = alg.generate_keypair()
    results.append(
        time_operation(
            f"{label}.sign",
            lambda: alg.sign(MESSAGE, secret_key),
            iterations=SIGN_ITERATIONS,
            extra=extra,
        )
    )

    signatures = [alg.sign(MESSAGE, secret_key) for _ in range(VERIFY_ITERATIONS)]
    signature_iter = iter(signatures)
    results.append(
        time_operation(
            f"{label}.verify",
            lambda: alg.verify(MESSAGE, next(signature_iter), public_key),
            iterations=VERIFY_ITERATIONS,
            warmup_iterations=0,
            extra=extra,
        )
    )

    return results


def benchmark_ml_dsa(security_level: int) -> list[TimingStats]:
    dsa = MLDSA(security_level)
    size_extra = {
        "public_key_size_bytes": dsa.public_key_size,
        "secret_key_size_bytes": dsa.secret_key_size,
        "signature_size_bytes": dsa.signature_size,
    }
    return _benchmark_algorithm(f"ML-DSA-{security_level}", dsa, size_extra)


def benchmark_classical() -> list[TimingStats]:
    sig = ClassicalSignature()
    size_extra = {
        "public_key_size_bytes": sig.public_key_size,
        "secret_key_size_bytes": sig.secret_key_size,
        "signature_size_bytes": sig.signature_size,
    }
    return _benchmark_algorithm(sig.algorithm_name, sig, size_extra)


def main() -> None:
    all_results: list[TimingStats] = []
    for level in ML_DSA_SECURITY_LEVELS:
        all_results.extend(benchmark_ml_dsa(level))
    all_results.extend(benchmark_classical())

    print_table(all_results)
    output_path = write_results("benchmark_signatures", all_results)
    print(f"\nResults written to: {output_path}")


if __name__ == "__main__":
    main()
