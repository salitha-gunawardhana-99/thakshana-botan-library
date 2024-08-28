#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>
#include <botan/hex.h>
#include <iostream>

int main() {
    Botan::AutoSeeded_RNG rng;

    // Generate RSA private key
    Botan::RSA_PrivateKey private_key(rng, 2048);

    // Extract public key from private key
    Botan::RSA_PublicKey public_key(private_key);

    // Message to sign
    std::string message = "Hello, this is a signed message.";

    // Hash the message
    std::unique_ptr<Botan::HashFunction> hash_function = Botan::HashFunction::create("SHA-256");
    hash_function->update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    std::vector<uint8_t> message_hash = hash_function->final_stdvec();

    // Sign the hash
    Botan::PK_Signer signer(private_key, rng, "EMSA-PKCS1-v1_5(SHA-256)");
    std::vector<uint8_t> signature = signer.sign_message(message_hash, rng);

    // Hex encode the signature
    std::string hex_signature = Botan::hex_encode(signature);

    // Verify the signature
    Botan::PK_Verifier verifier(public_key, "EMSA-PKCS1-v1_5(SHA-256)");
    bool valid = verifier.verify_message(message_hash, signature);

    // Output the results
    std::cout << "Message: " << message << std::endl;
    std::cout << "Signature: " << hex_signature << std::endl;
    std::cout << "Verification: " << (valid ? "valid" : "invalid") << std::endl;

    return 0;
}