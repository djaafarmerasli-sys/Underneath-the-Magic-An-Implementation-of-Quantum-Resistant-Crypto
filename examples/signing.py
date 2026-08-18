"""
signing.py -- minimal ML-DSA digital-signature demo
========================================================

Run with:   python examples/signing.py

Demonstrates the three ML-DSA operations, plus what a forgery/tamper attempt
looks like from the verifier's side:

    generate_keypair()                       -- create a signing identity
    sign(message, secret_key)                -- prove authorship
    verify(message, signature, public_key)   -- confirm authorship

SAFE OUTPUT ONLY: this script never prints the private key or the full
signature -- only sizes and boolean verification results.
"""

from __future__ import annotations

from pqcrypto.signatures import MLDSA


def main() -> None:
    security_level = 65
    dsa = MLDSA(security_level)
    print(f"ML-DSA parameter set: ML-DSA-{dsa.security_level}")

    public_key, secret_key = dsa.generate_keypair()
    print(f"Public key size:  {len(public_key)} bytes")
    print(f"Secret key size:  {len(secret_key)} bytes")

    message = b"This message was signed by the ML-DSA secret key holder."
    signature = dsa.sign(message, secret_key)
    print(f"Signature size:   {len(signature)} bytes")

    valid = dsa.verify(message, signature, public_key)
    print(f"Verification of the authentic message: {valid}")
    assert valid, "an untampered signature must verify"

    # Now show what happens when the message is altered after signing --
    # the same signature must NOT verify against the modified message.
    tampered_message = message + b" Also, please transfer all funds."
    still_valid = dsa.verify(tampered_message, signature, public_key)
    print(f"Verification of the tampered message:  {still_valid}")
    assert not still_valid, "a signature must not verify against a different message"


if __name__ == "__main__":
    main()
