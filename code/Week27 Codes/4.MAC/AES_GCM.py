import botan3 as bt
import os

# Function to encrypt a message
def encrypt_message(message, key):
    cipher = bt.SymmetricCipher('AES-128/GCM')
    cipher.set_key(key)
    iv = os.urandom(16)
    cipher.start(iv)
    ciphertext =cipher.finish(message.encode('utf-8'))
    return iv,ciphertext

# Function to decrypt a message
def decrypt_message(ciphertext, key,iv):
    cipher = bt.SymmetricCipher('AES-128/GCM',False)
    cipher.set_key(key)
    cipher.start(iv)
    plaintext =cipher.finish(ciphertext)
    return plaintext.decode()

def HMAC(key,message):
    mac = bt.MsgAuthCode("HMAC(SHA-256)")
    mac.set_key(key)
    mac.update(message)
    return mac.final().hex()

# Example usage
if __name__ == '__main__':
    key = os.urandom(16) # Replace with your own key
    message = "This is very confidential."

    iv,encrypted = encrypt_message(message, key)
    alis_tag = HMAC(key,encrypted)
    bob_tag = HMAC(key,encrypted)
    print(f'Alis Mac code: {alis_tag}')
    print(f'Bob Mac code: {bob_tag}')

    if(alis_tag==bob_tag):
        decrypted = decrypt_message(encrypted, key,iv)
        print(f'Decrypted Message: {decrypted}')
    else:
        print("The message has been tampered")
    

    
    