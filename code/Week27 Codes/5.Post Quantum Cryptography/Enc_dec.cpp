#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/rng.h>
#include <botan/kyber.h>
#include <memory>
#include <botan/system_rng.h>
#include <array>
#include <iostream>

int main() {
   const size_t shared_key_len = 32;
   const std::string kdf = "HKDF(SHA-512)";

   Botan::System_RNG rng;

   std::array<uint8_t, 16> salt;
   rng.randomize(salt);
   std::cout<<Botan::hex_encode(salt)<<std::endl;
   

   Botan::Kyber_PrivateKey priv_key(rng, Botan::KyberMode::Kyber512_R3);
   auto pub_key = priv_key.public_key();

   
   Botan::PK_KEM_Encryptor enc(*pub_key, kdf);

   const auto kem_result = enc.encrypt(rng, shared_key_len, salt);

   Botan::PK_KEM_Decryptor dec(priv_key, rng, kdf);

   auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);
    std::cout<<Botan::hex_encode(dec_shared_key)<<std::endl;
   if(dec_shared_key != kem_result.shared_key()) {
      std::cout << "Shared keys differ\n";
      return 1;
   }
   std::cout<<"Hii\n";

   return 0;
}