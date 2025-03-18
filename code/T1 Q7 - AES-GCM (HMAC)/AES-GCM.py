import botan3 as bt
import os

# Function to encrypt a message
def aes256_enc(ptext: str, key: bytes, iv: bytes) -> bytes:
    """Encrypts plaintext using AES-256/GCM."""
    cipher = bt.SymmetricCipher('AES-256/GCM')
    cipher.set_key(key)
    cipher.start(iv)
    ciphertext = cipher.finish(ptext.encode('utf-8'))
    return ciphertext

# Function to decrypt a message
def aes256_dec(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    """Decrypts ciphertext using AES-256/GCM."""
    cipher = bt.SymmetricCipher('AES-256/GCM', False)
    cipher.set_key(key)
    cipher.start(iv)
    plaintext = cipher.finish(ciphertext)
    return plaintext.decode('utf-8')

def main():
    # Create a random number generator
    rng = bt.RandomNumberGenerator()

    # Generate a 256-bit key and a 12-byte IV
    key_size = 32  # 256 bits
    iv_size = 12   # Recommended length for AES-GCM IV

    key = rng.get(key_size)
    iv = rng.get(iv_size)

    message = "This is a very private message"

    # Encrypt the message
    cipher_array = aes256_enc(message, key, iv)
    cipher_output = cipher_array.hex()
    print(f"_Encrypted (hex): {cipher_output}")

    # Decrypt the message
    decrypted_msg = aes256_dec(bytes.fromhex(cipher_output), key, iv)
    print(f"Decrypted output: {decrypted_msg}")

if __name__ == "__main__":
    main()
