import botan3 as botan
import os

def main():
    # Create a random number generator instance
    rng = botan.RandomNumberGenerator()

    # Define elliptic curve domain and key derivation function
    ec_domain = 'secp521r1'
    key_derivation_function = 'HKDF(SHA-256)'

    # Generate ECDH key pairs for two parties
    private_key_a = botan.PrivateKey.create('ECDH', ec_domain, rng)
    private_key_b = botan.PrivateKey.create('ECDH', ec_domain, rng)

    # Create key agreement objects for both parties using their private keys
    key_agreement_a = botan.PKKeyAgreement(private_key_a, key_derivation_function)
    key_agreement_b = botan.PKKeyAgreement(private_key_b, key_derivation_function)

    # Generate a random salt for key derivation
    salt_length = 16  # Length of the salt in bytes
    salt = os.urandom(salt_length)

    # Derive shared secrets using the other's public key and salt
    shared_secret_a = key_agreement_a.agree(key_agreement_b.public_value(), 32, salt)
    shared_secret_b = key_agreement_b.agree(key_agreement_a.public_value(), 32, salt)

    # Verify if both derived shared secrets are identical
    if shared_secret_a != shared_secret_b:
        print("Key share failed!")
        return 1

    # Output the shared key in hexadecimal format
    print(f"Shared key:", shared_secret_a.hex())
    print("Key share successful!")

    return 0

if __name__ == "__main__":
    main()
