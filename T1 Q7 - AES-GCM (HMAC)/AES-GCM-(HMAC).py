import botan3 as botan
import os

# Function to encrypt a message
def aes256_enc(ptext: str, key: bytes, iv: bytes) -> bytes:
    """Encrypts plaintext using AES-256/GCM."""
    cipher = botan.SymmetricCipher('AES-256/GCM')
    cipher.set_key(key)
    cipher.start(iv)
    ciphertext = cipher.finish(ptext.encode('utf-8'))
    return ciphertext

# Function to decrypt a message
def aes256_dec(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    """Decrypts ciphertext using AES-256/GCM."""
    cipher = botan.SymmetricCipher('AES-256/GCM', False)
    cipher.set_key(key)
    cipher.start(iv)
    plaintext = cipher.finish(ciphertext)
    return plaintext.decode('utf-8')

# Function to compute HMAC
def compute_mac(msg: str, key: bytes) -> str:
    """Computes HMAC of a message using SHA-256."""
    mac = botan.MsgAuthCode("HMAC(SHA-256)")
    mac.set_key(key)
    mac.update(msg.encode('utf-8'))
    return mac.final().hex()

def main():
    # Generate a 256-bit key and a 12-byte IV
    key_size = 32  # 256 bits
    iv_size = 12   # Recommended length for AES-GCM IV

    key = os.urandom(key_size)
    iv = os.urandom(iv_size)

    message = "This message remains confidential."

    # Encrypt the message
    cipher_array = aes256_enc(message, key, iv)

    # Compute HMAC for the ciphertext
    cipher_output = cipher_array.hex()  # Convert ciphertext to hex string
    hmac = compute_mac(cipher_output, key)

    # Print encrypted message and HMAC
    print(f"_Encrypted (hex): {cipher_output}")
    print(f"____________HMAC: {hmac}")

    # For demonstration, assume we received the ciphertext and HMAC
    received_cipher_output = cipher_output
    received_hmac = hmac

    # Recompute HMAC for received ciphertext
    computed_hmac = compute_mac(received_cipher_output, key)

    # Verify HMAC
    if computed_hmac == received_hmac:
        # HMAC is valid, proceed with decryption
        decrypted_msg = aes256_dec(bytes.fromhex(received_cipher_output), key, iv)
        print(f"Decrypted output: {decrypted_msg}")
    else:
        # HMAC is invalid, data may have been tampered with
        print("The message has been tampered with.")

if __name__ == "__main__":
    main()
