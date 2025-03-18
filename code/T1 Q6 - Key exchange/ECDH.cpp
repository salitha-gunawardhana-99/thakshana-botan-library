#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

#include <iostream>

int main()
{
    Botan::AutoSeeded_RNG rng;

    // Define elliptic curve domain and key derivation function
    const auto ec_domain = Botan::EC_Group::from_name("secp521r1");
    const std::string key_derivation_function = "KDF2(SHA-256)";

    // Generate ECDH key pairs for two parties
    Botan::ECDH_PrivateKey private_key_a(rng, ec_domain);
    Botan::ECDH_PrivateKey private_key_b(rng, ec_domain);

    // Extract public keys for both parties
    const auto public_key_a = private_key_a.public_value();
    const auto public_key_b = private_key_b.public_value();

    // Create key agreement objects for both parties
    Botan::PK_Key_Agreement key_agreement_a(private_key_a, rng, key_derivation_function);
    Botan::PK_Key_Agreement key_agreement_b(private_key_b, rng, key_derivation_function);

    // Derive shared secrets
    const auto shared_secret_a = key_agreement_a.derive_key(32, public_key_b).bits_of();
    const auto shared_secret_b = key_agreement_b.derive_key(32, public_key_a).bits_of();

    // Verify if both shared secrets match
    if (shared_secret_a != shared_secret_b)
    {
        std::cout << "Key share failed!\n";
        return 1;
    }

    // Output the shared key
    std::cout << "Shared key: " << Botan::hex_encode(shared_secret_a) << "\n";
    std::cout << "Key share successful!\n";

    return 0;
}
