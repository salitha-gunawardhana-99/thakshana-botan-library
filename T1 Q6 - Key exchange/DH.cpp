#include <botan/auto_rng.h>
#include <botan/dl_group.h>
#include <botan/dh.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <iostream>

int main()
{
    Botan::AutoSeeded_RNG rng;

    // Define DH parameters (group and key derivation function)
    const std::string dh_params = "modp/ietf/2048"; // Use a 2048-bit DH group
    const std::string key_derivation_function = "KDF2(SHA-256)";

    // Create DH group
    Botan::DL_Group dh_group(dh_params);

    // Generate DH key pairs for two parties
    Botan::DH_PrivateKey private_key__a(rng, dh_group);
    Botan::DH_PrivateKey private_key__b(rng, dh_group);

    // Extract public keys for both parties
    const auto public_key__a = private_key__a.public_value();
    const auto public_key__b = private_key__b.public_value();

    // Create key agreement objects for both parties
    Botan::PK_Key_Agreement key_agreement__a(private_key__a, rng, key_derivation_function);
    Botan::PK_Key_Agreement key_agreement__b(private_key__b, rng, key_derivation_function);

    // Derive shared secrets
    const auto shared_secret__a = key_agreement__a.derive_key(32, public_key__b).bits_of();
    const auto shared_secret__b = key_agreement__b.derive_key(32, public_key__a).bits_of();

    // Verify if both shared secrets match
    if (shared_secret__a != shared_secret__b)
    {
        std::cout << "Key share failed!\n";
        return 1;
    }

    // Output the shared key
    std::cout << "Shared key: " << Botan::hex_encode(shared_secret__a) << "\n";
    std::cout << "Key share successful!\n";

    return 0;
}
