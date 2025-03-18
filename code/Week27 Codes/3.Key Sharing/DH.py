import botan3 as botan
import secrets
import os

rng = botan.RandomNumberGenerator()
salt_length = 16  # Adjust the length as needed
salt = os.urandom(salt_length)

# Generate DH parameters for Alice and Bob
alice_priv = botan.PrivateKey.create('DH', 'modp/ietf/2048',rng)
bob_priv = botan.PrivateKey.create('DH', 'modp/ietf/2048',rng)

alice_pub = botan.PKKeyAgreement(alice_priv, 'KDF2(SHA-256)')
bob_pub = botan.PKKeyAgreement(bob_priv, 'KDF2(SHA-256)')

# Alice and Bob compute the shared key using other's public key
alice_shared_key = alice_pub.agree(bob_pub.public_value(),32,salt)
bob_shared_key = bob_pub.agree(alice_pub.public_value(),32,salt)

# Convert shared keys to hex strings for display
alice_shared_key_hex = alice_shared_key.hex()
bob_shared_key_hex = bob_shared_key.hex()

print("Alice's Shared Key:", alice_shared_key_hex)
print("Bob's Shared Key:", bob_shared_key_hex)

# Verify if both shared keys are identical
if (alice_shared_key_hex==bob_shared_key_hex):
    print("Key sharing Succesful")
assert alice_shared_key_hex == bob_shared_key_hex, "Shared keys do not match!"
