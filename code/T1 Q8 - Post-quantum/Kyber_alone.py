import botan3 as botan
import os

def main():
    # Create a random number generator instance
    rng = botan.RandomNumberGenerator()

    # Kyber key generation
    kyber_private_key = botan.PrivateKey.create('Kyber', 'Kyber-512-r3', rng)
    kyber_public_key = kyber_private_key.get_public_key()

    # Define key derivation function and generate salt
    kdf = "HKDF(SHA-512)"
    salt = os.urandom(16)

    # Key encapsulation
    enc = botan.KemEncrypt(kyber_public_key, kdf)
    kem_shared, encapsulated_key = enc.create_shared_key(rng, salt, 32)

    # Key decapsulation
    dec = botan.KemDecrypt(kyber_private_key, kdf)
    dec_shared = dec.decrypt_shared_key(salt, 32, encapsulated_key)

    # Output results
    print("___Decrypted shared key:", dec_shared.hex())
    print("Encapsulated shared key:", kem_shared.hex())

if __name__ == "__main__":
    main()
