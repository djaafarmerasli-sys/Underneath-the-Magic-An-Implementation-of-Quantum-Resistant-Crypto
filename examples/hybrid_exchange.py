"""
hybrid_exchange.py -- hybrid classical + ML-KEM key establishment demo
============================================================================

Run with:   python examples/hybrid_exchange.py

Demonstrates pqcrypto.hybrid.key_exchange combining X25519 (classical) and
ML-KEM (post-quantum) into one final session key via HKDF:

    classical shared secret  +  ML-KEM shared secret  ->  KDF  ->  session key

The point of the hybrid construction: the final session key stays secret as
long as AT LEAST ONE of the two underlying mechanisms remains unbroken. This
script demonstrates that concretely by tampering with just the ML-KEM
ciphertext component and showing the two sides then derive DIFFERENT keys --
i.e. the ML-KEM half is actually load-bearing, not decorative.

SAFE OUTPUT ONLY: never prints the actual session key -- only its length and
whether both sides agree.
"""

from __future__ import annotations

import dataclasses

from pqcrypto.hybrid.key_exchange import HybridKeyExchange


def main() -> None:
    ml_kem_security_level = 768
    alice = HybridKeyExchange(ml_kem_security_level=ml_kem_security_level)
    bob = HybridKeyExchange(ml_kem_security_level=ml_kem_security_level)

    bob_public, bob_secret = bob.generate_keypair()
    print("Classical algorithm:   X25519")
    print(f"ML-KEM parameter set:  ML-KEM-{ml_kem_security_level}")

    # --- Normal handshake: both sides must agree. ---
    ciphertext, alice_key = alice.initiate(bob_public)
    bob_key = bob.respond(bob_secret, ciphertext)

    print(f"Session key length:    {len(alice_key)} bytes")
    print(f"Alice and Bob agree on the session key: {alice_key == bob_key}")
    assert alice_key == bob_key

    # --- Demonstrate the ML-KEM component is load-bearing: tamper with
    #     JUST the ML-KEM ciphertext and show the derived keys now diverge,
    #     even though the classical (X25519) component is untouched. ---
    tampered_pq = bytearray(ciphertext.pq_ciphertext)
    tampered_pq[0] ^= 0xFF
    tampered_ciphertext = dataclasses.replace(ciphertext, pq_ciphertext=bytes(tampered_pq))

    bob_key_after_tamper = bob.respond(bob_secret, tampered_ciphertext)
    print(
        "Session keys still match after tampering with the ML-KEM "
        f"component only: {alice_key == bob_key_after_tamper}"
    )
    assert alice_key != bob_key_after_tamper, (
        "tampering the ML-KEM ciphertext must change the derived session key"
    )


if __name__ == "__main__":
    main()
