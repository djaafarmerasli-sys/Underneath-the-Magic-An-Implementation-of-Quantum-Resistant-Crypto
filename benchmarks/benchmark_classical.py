"""
benchmark_classical.py -- classical vs. post-quantum side-by-side comparison
==================================================================================

Run with:   python benchmarks/benchmark_classical.py

Benchmarks the project's classical baselines (X25519 for key establishment,
Ed25519 for signatures) directly alongside their post-quantum counterparts
(ML-KEM-768, ML-DSA-65 -- this project's default parameter sets) using the
same measurement methodology as benchmark_kem.py / benchmark_signatures.py,
and reports the size overhead ML-KEM/ML-DSA carry relative to the classical
baseline.

IMPORTANT -- WHAT THIS COMPARISON DOES AND DOES NOT MEAN
--------------------------------------------------------------
X25519 and ML-KEM both solve "establish a shared secret," so their
key-generation/establishment timings and artifact sizes are directly
comparable. The same is true for Ed25519 and ML-DSA on signing/verification.
That is the full extent of the comparison this script makes.

It does NOT mean every operation across the two families is interchangeable:
X25519 is a raw Diffie-Hellman primitive (see pqcrypto.kem.classical_kem's
DHKEM adaptation) while ML-KEM is natively a KEM; the two achieve comparable
end results through different shapes of operation. Timing numbers for
"key establishment" below measure each algorithm's OWN complete operation
(X25519: one DH computation; ML-KEM: encapsulate+decapsulate), not identical
underlying math.

Results are printed as a table and written as JSON to
data/benchmark_results/benchmark_classical.json. As with every benchmark in
this project, these numbers are specific to this run, this machine, and
these installed library versions -- not a universal or vendor-verified
performance claim.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bench_common import TimingStats, print_table, time_operation, write_results

from pqcrypto.kem.classical_kem import ClassicalKEM
from pqcrypto.kem.ml_kem import MLKEM
from pqcrypto.signatures.classical_signature import ClassicalSignature
from pqcrypto.signatures.ml_dsa import MLDSA

MESSAGE = b"classical vs. post-quantum comparison message" * 5

KEYGEN_ITERATIONS = 50
ESTABLISH_ITERATIONS = 50
SIGN_ITERATIONS = 50
VERIFY_ITERATIONS = 50


def benchmark_kem_pair() -> list[TimingStats]:
    results: list[TimingStats] = []

    for label, kem in (("X25519 (classical)", ClassicalKEM()), ("ML-KEM-768 (PQC)", MLKEM(768))):
        size_extra = {
            "public_key_size_bytes": kem.public_key_size,
            "secret_key_size_bytes": kem.secret_key_size,
            "ciphertext_size_bytes": kem.ciphertext_size,
            "shared_secret_size_bytes": kem.shared_secret_size,
        }
        results.append(
            time_operation(
                f"{label}.generate_keypair",
                lambda kem=kem: kem.generate_keypair(),
                iterations=KEYGEN_ITERATIONS,
                extra=size_extra,
            )
        )
        public_key, secret_key = kem.generate_keypair()

        def full_establishment(kem=kem, public_key=public_key, secret_key=secret_key):
            """One complete key-establishment round for this algorithm --
            encapsulate() + decapsulate() for a KEM, which is the operation
            that is actually comparable between X25519-as-DHKEM and ML-KEM."""
            ciphertext, _ = kem.encapsulate(public_key)
            kem.decapsulate(secret_key, ciphertext)

        results.append(
            time_operation(
                f"{label}.establish (encapsulate+decapsulate)",
                full_establishment,
                iterations=ESTABLISH_ITERATIONS,
                extra=size_extra,
            )
        )

    return results


def benchmark_signature_pair() -> list[TimingStats]:
    results: list[TimingStats] = []

    for label, alg in (("Ed25519 (classical)", ClassicalSignature()), ("ML-DSA-65 (PQC)", MLDSA(65))):
        size_extra = {
            "public_key_size_bytes": alg.public_key_size,
            "secret_key_size_bytes": alg.secret_key_size,
            "signature_size_bytes": alg.signature_size,
        }
        results.append(
            time_operation(
                f"{label}.generate_keypair",
                lambda alg=alg: alg.generate_keypair(),
                iterations=KEYGEN_ITERATIONS,
                extra=size_extra,
            )
        )
        public_key, secret_key = alg.generate_keypair()
        results.append(
            time_operation(
                f"{label}.sign",
                lambda alg=alg, secret_key=secret_key: alg.sign(MESSAGE, secret_key),
                iterations=SIGN_ITERATIONS,
                extra=size_extra,
            )
        )

        signatures = [alg.sign(MESSAGE, secret_key) for _ in range(VERIFY_ITERATIONS)]
        signature_iter = iter(signatures)
        results.append(
            time_operation(
                f"{label}.verify",
                lambda alg=alg, public_key=public_key: alg.verify(
                    MESSAGE, next(signature_iter), public_key
                ),
                iterations=VERIFY_ITERATIONS,
                warmup_iterations=0,
                extra=size_extra,
            )
        )

    return results


def print_size_overhead_summary() -> None:
    classical_kem, pq_kem = ClassicalKEM(), MLKEM(768)
    classical_sig, pq_sig = ClassicalSignature(), MLDSA(65)

    print("\nSize overhead of PQC vs. classical (this project's default parameter sets):")
    print(
        f"  ML-KEM-768 public key is {pq_kem.public_key_size / classical_kem.public_key_size:.1f}x "
        f"the size of an X25519 public key "
        f"({pq_kem.public_key_size} vs {classical_kem.public_key_size} bytes)"
    )
    print(
        f"  ML-KEM-768 ciphertext is {pq_kem.ciphertext_size / classical_kem.ciphertext_size:.1f}x "
        f"the size of an X25519 DHKEM ciphertext "
        f"({pq_kem.ciphertext_size} vs {classical_kem.ciphertext_size} bytes)"
    )
    print(
        f"  ML-DSA-65 public key is {pq_sig.public_key_size / classical_sig.public_key_size:.1f}x "
        f"the size of an Ed25519 public key "
        f"({pq_sig.public_key_size} vs {classical_sig.public_key_size} bytes)"
    )
    print(
        f"  ML-DSA-65 signature is {pq_sig.signature_size / classical_sig.signature_size:.1f}x "
        f"the size of an Ed25519 signature "
        f"({pq_sig.signature_size} vs {classical_sig.signature_size} bytes)"
    )


def main() -> None:
    all_results: list[TimingStats] = []
    all_results.extend(benchmark_kem_pair())
    all_results.extend(benchmark_signature_pair())

    print_table(all_results)
    print_size_overhead_summary()
    output_path = write_results("benchmark_classical", all_results)
    print(f"\nResults written to: {output_path}")


if __name__ == "__main__":
    main()
