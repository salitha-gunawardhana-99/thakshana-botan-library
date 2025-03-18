#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <iostream>

int main()
{
   Botan::AutoSeeded_RNG rng;

   // Generate ECDSA keypair
   const auto group = Botan::EC_Group::from_name("secp521r1");
   Botan::ECDSA_PrivateKey private_key(rng, group);
   auto public_key = private_key.public_key();

   const std::string message("This is a signed message!");

   // Sign data
   Botan::PK_Signer signer(private_key, rng, "SHA-256");
   signer.update(message);
   std::vector<uint8_t> signature = signer.signature(rng);

   // Output the message, signature and public key
   std::cout << "\nMessage: " << message << std::endl;
   std::cout << "\nSignature: " << Botan::hex_encode(signature) << std::endl;

   std::string public_key_pem = Botan::X509::PEM_encode(*public_key);
   std::cout << "\nPublic Key (PEM):\n"
             << public_key_pem << std::endl;

   // Simulating the receiver's process of verifying the signature

   // Decode the public key
   Botan::DataSource_Memory key_data(public_key_pem);
   std::unique_ptr<Botan::Public_Key> loaded_public_key(Botan::X509::load_key(key_data));

   // Verify the signature
   Botan::PK_Verifier verifier(*loaded_public_key, "SHA-256");
   verifier.update(message);
   bool valid = verifier.check_signature(signature);

   std::cout << "The signature is " << (valid ? "valid.\n" : "invalid.\n") << std::endl;

   return 0;
}
