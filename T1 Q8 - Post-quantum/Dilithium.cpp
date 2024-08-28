// Purpose: Dilithium is a digital signature scheme designed for creating and verifying signatures.

#include <botan/auto_rng.h>
#include <botan/dilithium.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h> // Include for X.509 key handling
#include <iostream>

int main()
{
    Botan::AutoSeeded_RNG rng;

    // Generate Dilithium keypair
    Botan::Dilithium_PrivateKey private_key(rng, Botan::DilithiumMode::Dilithium4x4);
    auto public_key = private_key.public_key();

    // Message to sign
    const std::string message = "This is a signed message!";
    Botan::secure_vector<uint8_t> message_vec(message.begin(), message.end());

    // Sign the message
    Botan::PK_Signer signer(private_key, rng, "");
    signer.update(message_vec);
    std::vector<uint8_t> signature = signer.signature(rng);

    // Output the message
    std::cout << "\nMessage: " << message << std::endl;

    // Output the signature in hexadecimal format
    std::cout << "\nSignature:\n"
              << Botan::hex_encode(signature) << std::endl;

    // Export and output the public key in PEM format
    std::string public_key_pem = Botan::X509::PEM_encode(*public_key);
    std::cout << "\nPublic Key (PEM):\n"
              << public_key_pem << std::endl;

    // Verify the signature
    Botan::PK_Verifier verifier(*public_key, "");
    verifier.update(message_vec);
    std::cout << "The signature is " << (verifier.check_signature(signature) ? "valid." : "invalid.") << std::endl;

    return 0;
}
