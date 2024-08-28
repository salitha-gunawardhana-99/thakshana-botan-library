import botan3 as bt
import os

# Function to encrypt a message
def encrypt_message(message, key):
    cipher = bt.SymmetricCipher('AES-128/CBC')
    cipher.set_key(key)
    iv = os.urandom(16)
    cipher.start(iv)
    ciphertext =cipher.finish(message.encode('utf-8'))
    return iv,ciphertext

# Function to decrypt a message
def decrypt_message(ciphertext, key,iv):
    cipher = bt.SymmetricCipher('AES-128/CBC',False)
    cipher.set_key(key)
    cipher.start(iv)
    plaintext =cipher.finish(ciphertext)
    return plaintext.decode()


if __name__ == '__main__':
    key = os.urandom(16) # Key
    message = "This is very confidential."

    iv,encrypted = encrypt_message(message, key)
    decrypted = decrypt_message(encrypted, key,iv)

    print(f'Original Message: {message}')
    print(f'Encrypted Message: {encrypted}')
    print(f'Decrypted Message: {decrypted}')