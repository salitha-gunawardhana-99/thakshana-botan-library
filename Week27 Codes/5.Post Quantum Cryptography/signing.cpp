#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <iostream>
#include <botan/dilithium.h>

int main() {
Botan::AutoSeeded_RNG rng;
// Generate ECDSA keypair
Botan::Dilithium_PrivateKey key(rng, Botan::DilithiumMode::Mode::Dilithium4x4);
const std::string message("This is a tasty burger!");
// sign data
Botan::PK_Signer signer(key,rng,"");
signer.update(message);
std::vector<uint8_t> signature = signer.signature(rng);
std::cout << "Signature:\n" << Botan::hex_encode(signature);
// now verify the signature
Botan::PK_Verifier verifier(key, "");
verifier.update(message);
std::cout << "is " << (verifier.check_signature(signature) ? "valid" : "invalid")<<std::endl;
return 0;

}