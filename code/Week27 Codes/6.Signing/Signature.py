import botan3 as botan
from base64 import b64encode

def main():
    rng = botan.RandomNumberGenerator()

    # Generate RSA private key
    rsa_priv_key = botan.PrivateKey.create("RSA", "2048", rng)

    # Extract public key from private key
    rsa_pub_key = rsa_priv_key.get_public_key()

    # Message to sign
    message = "Hello, this is a signed message."

    # Sign the message
    signer = botan.PKSign(rsa_priv_key, 'EMSA-PKCS1-v1_5(SHA-256)')
    signer.update(message)
    signature = signer.finish(rng)

    # Hex encode the signature
    hex_signature = b64encode(signature).decode()

    # Verify the signature
    verifier = botan.PKVerify(rsa_pub_key, 'EMSA-PKCS1-v1_5(SHA-256)')
    verifier.update(message)
    valid = verifier.check_signature(signature)

    # Output the results
    print("Message:", message)
    print("Signature:", hex_signature)
    print("Verification:", "valid" if valid else "invalid")

if __name__ == "__main__":
    main()