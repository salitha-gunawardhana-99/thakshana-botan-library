import botan3 as botan
from colorama import Fore

def generate_rsa_keypair():
    rng = botan.RandomNumberGenerator()
    rsa_private_key = botan.PrivateKey.create('rsa', 2048, rng)
    rsa_public_key = rsa_private_key.get_public_key()
    return rsa_private_key, rsa_public_key

# Function to encrypt a message with RSA public key
def encrypt_message_rsa(message, public_key):
    rng = botan.RandomNumberGenerator()
    encrypt_obj = botan.PKEncrypt(public_key,'OAEP(SHA-256)')
    cipher = encrypt_obj.encrypt(message.encode(), rng)
    return cipher

# Function to decrypt a message with RSA private key
def decrypt_message_rsa(cipher, private_key):
    plain_t_obj = botan.PKDecrypt(private_key,'OAEP(SHA-256)')
    plaintext = plain_t_obj.decrypt(cipher)
    return plaintext.decode()


if __name__ == '__main__':
    # Generate RSA key pair
    private_key, public_key = generate_rsa_keypair()

    # Message to be encrypted
    message = "This is a very confidential message"

    # Encrypt message with RSA public key
    encrypted = encrypt_message_rsa(message, public_key)

    # Decrypt message with RSA private key
    decrypted = decrypt_message_rsa(encrypted, private_key)

    print(f'Original Message: {message}')
    print(f'Encrypted Message: {Fore.RED+encrypted.hex()}')
    print(Fore.WHITE+f'Decrypted Message: {decrypted}')

    guessed_msg = "This is a very confidential messag"
    # Encrypt message with RSA public key
    guess_encrypted = encrypt_message_rsa(guessed_msg, public_key)

    # Decrypt message with RSA private key
    guess_decrypted = decrypt_message_rsa(encrypted, private_key)

    print()
    print(f'Guessed Message: {Fore.WHITE+guessed_msg}')
    print(f'Guessed Encrypted Message: {Fore.RED+guess_encrypted.hex()}')
    #print(f'Decrypted Message: {decrypted}')

