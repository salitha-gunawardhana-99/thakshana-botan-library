import botan3 as botan
import os

def main():
    # Create a random number generator
    rng = botan.RandomNumberGenerator()

    # Generate a Kyber key pair
    kyber_key_size = 'Kyber-512-r3'  # Define Kyber parameters
    priv_key = botan.PrivateKey.create('Kyber', kyber_key_size, rng)
    pub_key = priv_key.get_public_key()

    # Encryptor setup with Kyber
    enc = botan.KemEncrypt(pub_key, 'HKDF(SHA-512)')
    salt = os.urandom(16)  # Generate a random salt
    shared_key_len = 32  # Length of shared key for AES
    kem_shared_key, encapped_key = enc.create_shared_key(rng, salt, shared_key_len)

    # Decryptor setup with Kyber
    dec = botan.KemDecrypt(priv_key, 'HKDF(SHA-512)')
    dec_shared_key = dec.decrypt_shared_key(salt, shared_key_len, encapped_key)

    # Verify the shared key
    if dec_shared_key != kem_shared_key:
        print("Shared keys differ")
        return 1

    # Use the shared key for AES encryption
    shared_key = kem_shared_key

    # Generate a 12-byte IV
    iv_size = 12
    iv = rng.get(iv_size)

    message = "This is a very private message"

    # Encrypt the message using AES-256/GCM
    cipher = botan.SymmetricCipher('AES-256/GCM')
    cipher.set_key(shared_key)
    cipher.start(iv)
    ciphertext = cipher.finish(message.encode('utf-8'))
    cipher_output = ciphertext.hex()
    print(f"_Encrypted (hex): {cipher_output}")

    # Decrypt the message using AES-256/GCM
    cipher = botan.SymmetricCipher('AES-256/GCM', False)
    cipher.set_key(shared_key)
    cipher.start(iv)
    plaintext = cipher.finish(bytes.fromhex(cipher_output))
    print(f"Decrypted output: {plaintext.decode('utf-8')}")

if __name__ == "__main__":
    main()
