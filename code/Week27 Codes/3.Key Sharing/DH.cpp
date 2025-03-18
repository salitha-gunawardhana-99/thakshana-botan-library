#include <botan/auto_rng.h>
#include <botan/dh.h>
#include <botan/hex.h>
#include <botan/dl_group.h>
#include <botan/pubkey.h>
#include <iostream>
using namespace Botan;

int main()
{
    AutoSeeded_RNG rng;

    // Generate parameters for DH
    Botan::DL_Group dh_grp("modp/ietf/2048");

    // Generate Alice's keys
    Botan::DH_PrivateKey alice_priv(rng, dh_grp);
    std::vector<uint8_t> alice_pub_key = alice_priv.public_value();

    // Generate Bob's keys
    Botan::DH_PrivateKey bob_priv(rng, DL_Group("modp/ietf/2048"));
    std::vector<uint8_t> bob_pub_key = bob_priv.public_value();

    // Both parties share their public keys
    //  Alice calculates shared key using Bob's public key
    Botan::PK_Key_Agreement alice_agree(alice_priv, rng, "KDF2(SHA-256)");
    Botan::SymmetricKey alice_shared_key = alice_agree.derive_key(32, bob_pub_key);

    // Bob calculates shared key using Alice's public key
    Botan::PK_Key_Agreement bob_agree(bob_priv, rng, "KDF2(SHA-256)");
    Botan::SymmetricKey bob_shared_key = bob_agree.derive_key(32, alice_pub_key);

    // Convert shared keys to hex strings for display
    std::cout << "Alice's Shared Key: " << hex_encode(alice_shared_key) << std::endl;
    std::cout << "Bob's Shared Key: " << hex_encode(bob_shared_key) << std::endl;
    if (alice_shared_key == bob_shared_key)
    {
        std::cout << "Succesfully shared the key\n";
    }
    else
    {
        std::cout << "Key sharing is not succeess\n";
    }

    return 0;
}