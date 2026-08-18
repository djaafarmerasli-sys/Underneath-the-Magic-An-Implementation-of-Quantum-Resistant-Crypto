"""
basic_kem.py -- minimal ML-KEM key-encapsulation demo
==========================================================

Run with:   python examples/basic_kem.py

Demonstrates the three ML-KEM operations end to end:

    generate_keypair()   -- the recipient creates a public/secret keypair
    encapsulate()        -- the sender mints a shared secret + ciphertext
    decapsulate()         -- the recipient recovers the same shared secret

This is deliberately the smallest possible example: no key storage, no
hybrid combination with classical crypto, no file encryption -- just ML-KEM
in isolation. See hybrid_exchange.py and file_encryption.py for how this
building block fits into the rest of the project.

SAFE OUTPUT ONLY: this script never prints the actual public key, secret
key, ciphertext, or shared secret bytes -- only sizes and an equality
result. Printing cryptographic material, even in a "just a demo" script, is
a habit worth never forming.
"""

from __future__ import annotations

from pqcrypto.kem import MLKEM


def main() -> None:
    security_level = 768
    kem = MLKEM(security_level)
    print(f"ML-KEM parameter set: ML-KEM-{kem.security_level}")

    # --- Recipient side: generate a keypair and publish the public half. ---
    public_key, secret_key = kem.generate_keypair()
    print(f"Recipient public key size:  {len(public_key)} bytes")
    print(f"Recipient secret key size:  {len(secret_key)} bytes")

    # --- Sender side: encapsulate against the recipient's public key. ---
    ciphertext, sender_secret = kem.encapsulate(public_key)
    print(f"Ciphertext size:            {len(ciphertext)} bytes")
    print(f"Shared secret size:         {len(sender_secret)} bytes")

    # --- Recipient side: decapsulate to recover the same shared secret. ---
    recipient_secret = kem.decapsulate(secret_key, ciphertext)

    secrets_match = sender_secret == recipient_secret
    print(f"Sender and recipient derived the same shared secret: {secrets_match}")
    assert secrets_match, "ML-KEM round trip failed -- this should never happen"


if __name__ == "__main__":
    main()
