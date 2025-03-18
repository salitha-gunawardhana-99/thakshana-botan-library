import botan3 as botan
import binascii

def main():
    # Create a random number generator
    rng = botan.RandomNumberGenerator()

    # Generate ECDSA keypair
    group = "secp521r1"
    private_key = botan.PrivateKey.create("ECDSA", group, rng)
    public_key = private_key.get_public_key()

    message = "This is a signed message!"

    # Sign the message
    signer = botan.PKSign(private_key, "SHA-256")
    signer.update(message)  # Ensure that the message is a string
    signature = signer.finish(rng)

    # Output the message, signature, and public key
    print(f"\nMessage: {message}")
    print(f"\nSignature: {binascii.hexlify(signature).decode()}")

    # Export public key in PEM format
    public_key_pem = public_key.to_pem()
    print(f"\nPublic Key (PEM):\n{public_key_pem}")

    # Simulating the receiver's process of verifying the signature

    # Load the public key from PEM
    loaded_public_key = botan.PublicKey.load(public_key_pem)

    # Verify the signature
    verifier = botan.PKVerify(loaded_public_key, "SHA-256")
    verifier.update(message)  # Ensure that the message is a string
    valid = verifier.check_signature(signature)

    print(f"The signature is {'valid.' if valid else 'invalid.'}")

if __name__ == "__main__":
    main()
