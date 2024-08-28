import botan3 as botan
from base64 import b64encode

def main():
    rng = botan.RandomNumberGenerator()

    # Generate RSA private key
    dilithium_priv_key = botan.PrivateKey.create("Dilithium", "", rng)

    # Extract public key from private key
    dilithium_pub_key = dilithium_priv_key.get_public_key()

    # Message to sign
    message = "Hello, this is a signed message."

    # Sign the message
    signer = botan.PKSign(dilithium_priv_key, '')
    signer.update(message)
    signature = signer.finish(rng)

    # Hex encode the signature
    hex_signature = b64encode(signature).decode()

    # Verify the signature
    verifier = botan.PKVerify(dilithium_pub_key, '')
    verifier.update(message)
    valid = verifier.check_signature(signature)

    # Output the results
    print("Message:", message)
    print("Signature:", hex_signature)
    print("Verification:", "valid" if valid else "invalid")

if __name__ == "__main__":
    main()