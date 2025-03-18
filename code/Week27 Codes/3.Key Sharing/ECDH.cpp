#include <botan/auto_rng.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <iostream>
using namespace Botan;

int main() {
    AutoSeeded_RNG rng;

    // Generate DH parameters
    Botan::EC_Group ec_grp("secp256r1");

    //Key generation
    Botan::ECDH_PrivateKey alice_priv(rng, ec_grp);
    std::vector<uint8_t> alice_pub_key = alice_priv.public_value();
    
    Botan::ECDH_PrivateKey bob_priv(rng, EC_Group("secp256r1"));
    std::vector<uint8_t> bob_pub_key = bob_priv.public_value();

    // Alice calculates shared key using Bob's public key
    Botan::PK_Key_Agreement alice_agree(alice_priv, rng,"KDF2(SHA-256)");
    Botan::SymmetricKey alice_shared_key = alice_agree.derive_key(32, bob_pub_key);

    // Bob calculates shared key using Alice's public key
    Botan::PK_Key_Agreement bob_agree(bob_priv, rng,"KDF2(SHA-256)");
    Botan::SymmetricKey bob_shared_key = bob_agree.derive_key(32, alice_pub_key);

    // Convert shared keys to hex strings for display
    std::cout << "Alice's Shared Key: " << hex_encode(alice_shared_key) << std::endl;
    std::cout << "Bob's Shared Key: " << hex_encode(bob_shared_key) << std::endl;

    if (alice_shared_key==bob_shared_key){
        std::cout<<"Succesfully shared the key\n";
    }
    else {
        std::cout<<"Key sharing is not succeess\n";
    }
    return 0;
}