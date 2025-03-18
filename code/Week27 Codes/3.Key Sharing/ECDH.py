import botan3 as botan
import os

if __name__ == "__main__":
    rng = botan.RandomNumberGenerator()

    # Key generation
    alice_private_key = botan.PrivateKey.create("ECDH", "secp256r1", rng)
    bob_private_key = botan.PrivateKey.create("ECDH", "secp256r1", rng)

    # Perform key derivation using the given private key and specified KDF
    alice_agreement = botan.PKKeyAgreement(alice_private_key, "KDF2(SHA-256)")
    bob_agreement = botan.PKKeyAgreement(bob_private_key, "KDF2(SHA-256)")

    # Random salt 
    salt = os.urandom(16)

    # Perform key agreement. person_agreement.public_value() is the public value that
    # should be passed to the other person
    # agree returns a key derived by the KDF.
    sA = alice_agreement.agree(bob_agreement.public_value(), 32, salt)
    sB = bob_agreement.agree(alice_agreement.public_value(), 32, salt)

    print("Shared Secret Alice:", sA.hex())
    print("Shared Secret Bob:", sB.hex())

    if sA == sB:
        print("Key agreement successful.")
    else:
        print("Key agreement failed.")