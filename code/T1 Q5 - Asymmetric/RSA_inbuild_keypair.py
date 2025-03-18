import botan3 as botan

def generate_rsa_keypair():
    rng = botan.RandomNumberGenerator()
    rsa_private_key = botan.PrivateKey.create('rsa', 2048, rng)
    rsa_public_key = rsa_private_key.get_public_key()
    return rsa_private_key, rsa_public_key

def encrypt(plaintext, public_key):
    try:
        rng = botan.RandomNumberGenerator()
        enc = botan.PKEncrypt(public_key, "OAEP(SHA-256)")
        ciphertext = enc.encrypt(plaintext.encode('utf-8'), rng)
        return ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return b''

def decrypt(ciphertext, private_key):
    try:
        rng = botan.RandomNumberGenerator()
        dec = botan.PKDecrypt(private_key, "OAEP(SHA-256)")
        plaintext = dec.decrypt(ciphertext).decode('utf-8')
        return plaintext
    except Exception as e:
        print(f"Decryption error: {e}")
        return ''

def print_hex(label, data):
    hex_data = data.hex()
    print(f'{label}{hex_data}')

def main():
    plaintext = "This message is to be encrypted using RSA"

    try:
        # Generate RSA key pair
        private_key, public_key = generate_rsa_keypair()

        # Encrypt with public key
        encrypted = encrypt(plaintext, public_key)
        print_hex("Encrypted: ", encrypted)

        # Decrypt with private key
        decrypted_text = decrypt(encrypted, private_key)
        print(f"Decrypted text: {decrypted_text}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
