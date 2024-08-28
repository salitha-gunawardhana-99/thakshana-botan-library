import botan3 as bt
import os

# Function to print data as hexadecimal
def print_hex(label, data):
    hex_data = data.hex()
    print(f'{label}: {hex_data}')

# Function to pad data to be a multiple of the block size
def pad(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

# Function to unpad data
def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

# Function to convert a string to bytes
def string_to_bytes(s):
    return s.encode('utf-8')

# Function to convert bytes to a string
def bytes_to_string(b):
    return b.decode('utf-8')

# Function to perform encryption
def encrypt(key, plaintext):
    try:
        cipher = bt.SymmetricCipher('AES-256/CBC')
        cipher.set_key(key)
        iv = os.urandom(16)  # 16 bytes IV for AES
        cipher.start(iv)
        padded_plaintext = pad(plaintext, 16)
        ciphertext = cipher.finish(padded_plaintext)
        print_hex("AES-256 ____plain text", padded_plaintext)
        print_hex("AES-256 encrypted text", ciphertext)
        return iv, ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return b'', b''

# Function to perform decryption
def decrypt(key, iv, ciphertext):
    try:
        cipher = bt.SymmetricCipher('AES-256/CBC', False)
        cipher.set_key(key)
        cipher.start(iv)
        plaintext = cipher.finish(ciphertext)
        unpadded_plaintext = unpad(plaintext)
        print_hex("AES-256 decrypted text", unpadded_plaintext)
        return unpadded_plaintext
    except Exception as e:
        print(f"Decryption error: {e}")
        return b''

def main():
    # Generate a random key for AES-256 (256 bits = 32 bytes)
    key = os.urandom(32)
    print(f"Generated Key: {key.hex()}\n")

    # The human-readable message to be encrypted
    message = "This message is to be encrypted using AES-256"
    plaintext = string_to_bytes(message)

    # Perform encryption
    iv, ciphertext = encrypt(key, plaintext)

    # Perform decryption
    decryptedtext = decrypt(key, iv, ciphertext)

    # Convert the decrypted text back to a string
    decrypted_message = bytes_to_string(decryptedtext)

    # Verify decryption matches original message
    if decrypted_message == message:
        print(f"\nReceived message: {message}")
        print("Decryption successful, message matches.\n")
    else:
        print("\nDecryption failed, message does not match.\n")

if __name__ == "__main__":
    main()
