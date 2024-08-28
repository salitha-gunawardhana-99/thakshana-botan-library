import botan3 as botan

# Function to encrypt plaintext
def encrypt(plaintext, public_key):
    try:
        rng = botan.RandomNumberGenerator()
        enc = botan.PKEncrypt(public_key, "OAEP(SHA-256)")
        ciphertext = enc.encrypt(plaintext.encode('utf-8'), rng)
        return ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return b''

# Function to decrypt ciphertext
def decrypt(ciphertext, private_key):
    try:
        dec = botan.PKDecrypt(private_key, "OAEP(SHA-256)")
        plaintext = dec.decrypt(ciphertext).decode('utf-8')
        return plaintext
    except Exception as e:
        print(f"Decryption error: {e}")
        return ''

# Function to print hex encoded data
def print_hex(label, data):
    hex_data = data.hex()
    print(f'{label}{hex_data}')

def main():
    plaintext = "This message is to be encrypted using RSA"
    print(f"_____Plaintext: {plaintext}")

    # Generate RSA key pair
    rng = botan.RandomNumberGenerator()
    rsa_private_key = botan.PrivateKey.create('rsa', 2048, rng)
    rsa_public_key = rsa_private_key.get_public_key()

    # Encrypt plaintext
    ciphertext = encrypt(plaintext, rsa_public_key)
    print_hex("Encrypted text: ", ciphertext)

    # Decrypt ciphertext
    decrypted_text = decrypt(ciphertext, rsa_private_key)

    # Print results
    print(f"Decrypted text: {decrypted_text}\n")

if __name__ == "__main__":
    main()
