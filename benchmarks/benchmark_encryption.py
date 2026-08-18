"""
benchmark_encryption.py -- AES-256-GCM throughput benchmark
=================================================================

Run with:   python benchmarks/benchmark_encryption.py

Benchmarks pqcrypto.encryption.aes encrypt()/decrypt() across representative
plaintext sizes (1 KiB, 1 MiB, 10 MiB, and 100 MiB), reporting timing,
throughput (MiB/s), and the fixed per-package overhead (nonce + auth tag)
AES-GCM adds regardless of plaintext size.

Results are printed as a table and written as JSON to
data/benchmark_results/benchmark_encryption.json.

METHODOLOGY
-------------
* Each size gets its own independently-generated random plaintext (not the
  same buffer reused/resliced across sizes).
* A fresh AES-256 key is used for this benchmark run; every individual
  encrypt() call still generates its own fresh nonce internally (see aes.py)
  -- this benchmark never reuses a nonce with a key, and never supplies its
  own nonce.
* Decryption is timed against pre-computed, valid ciphertext (encryption is
  excluded from the timed region for the decrypt series).
* Iteration counts shrink as plaintext size grows, to keep total benchmark
  runtime reasonable while still providing multiple independent samples at
  every size.
* This benchmark does NOT measure or report memory usage -- only wall-clock
  time, which is all that is actually instrumented here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bench_common import TimingStats, print_table, time_operation, write_results

from pqcrypto.encryption import aes
from pqcrypto.utils import randomness

KIB = 1024
MIB = 1024 * KIB

# (label, size in bytes, iterations). Iteration count drops as size grows so
# the 100 MiB case doesn't dominate total runtime.
SIZE_CASES = [
    ("1KiB", 1 * KIB, 200),
    ("1MiB", 1 * MIB, 30),
    ("10MiB", 10 * MIB, 10),
    ("100MiB", 100 * MIB, 3),
]

KEY = randomness.random_bytes(aes.KEY_SIZE)
OVERHEAD_BYTES = aes.NONCE_SIZE + aes.TAG_SIZE


def benchmark_size(label: str, size_bytes: int, iterations: int) -> list[TimingStats]:
    # pqcrypto.utils.randomness.random_bytes() intentionally caps requests at
    # 1 MiB (it's meant for application-level secrets like salts/key IDs, not
    # bulk data) -- benchmark plaintext isn't secret, so os.urandom() is used
    # directly here for sizes above that cap instead of loosening that limit.
    plaintext = os.urandom(size_bytes)
    results: list[TimingStats] = []

    throughput_extra = {"plaintext_size_bytes": size_bytes, "package_overhead_bytes": OVERHEAD_BYTES}

    encrypt_result = time_operation(
        f"encrypt.{label}",
        lambda: aes.encrypt(plaintext, KEY),
        iterations=iterations,
        warmup_iterations=min(2, iterations),
        extra=throughput_extra,
    )
    results.append(_with_throughput(encrypt_result, size_bytes))

    # Pre-compute one valid package per decrypt sample -- encryption cost
    # must not leak into the decrypt timing.
    packages = [aes.encrypt(plaintext, KEY) for _ in range(iterations)]
    package_iter = iter(packages)
    decrypt_result = time_operation(
        f"decrypt.{label}",
        lambda: aes.decrypt(next(package_iter), KEY),
        iterations=iterations,
        warmup_iterations=0,
        extra=throughput_extra,
    )
    results.append(_with_throughput(decrypt_result, size_bytes))

    return results


def _with_throughput(result: TimingStats, size_bytes: int) -> TimingStats:
    """Attach MiB/s throughput to a TimingStats' `extra` dict, derived from
    its already-measured mean time -- not independently measured."""
    from dataclasses import replace

    mib = size_bytes / MIB
    throughput = (mib / result.mean_seconds) if result.mean_seconds > 0 else float("inf")
    return replace(result, extra={**result.extra, "throughput_mib_per_second": round(throughput, 3)})


def main() -> None:
    all_results: list[TimingStats] = []
    for label, size_bytes, iterations in SIZE_CASES:
        all_results.extend(benchmark_size(label, size_bytes, iterations))

    print_table(all_results)
    print(f"\nFixed per-package overhead (nonce + auth tag): {OVERHEAD_BYTES} bytes")
    output_path = write_results("benchmark_encryption", all_results)
    print(f"Results written to: {output_path}")


if __name__ == "__main__":
    main()
