#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/rsa.h>
#include <iostream>

int main() {

   //std::string key_path = "/home/pasindu/work/crypto/C++-Programming/Learning2/ENC_DEC_Public/private_key.pem";
   
   std::string plaintext(
      "Key agreement is a scheme where two parties exchange public keys, after which it is possible for them to derive a secret key which is known only to the two of them.");
   std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
   Botan::AutoSeeded_RNG rng;
   
   //generate key-pair
   Botan::RSA_PrivateKey rsa_private_key(rng, 2048);
   const Botan::RSA_PublicKey& rsa_public_key = rsa_private_key;
   

   // encrypt with public key
   Botan::PK_Encryptor_EME enc(rsa_public_key, rng, "OAEP(SHA-256)");
   std::vector<uint8_t> ct = enc.encrypt(pt, rng);

   // decrypt with private key
   Botan::PK_Decryptor_EME dec(rsa_private_key, rng, "OAEP(SHA-256)");
   Botan::secure_vector<uint8_t> pt2 = dec.decrypt(ct);
   
   std::cout << "enc: " << Botan::hex_encode(ct) <<std::endl<< "dec: " << Botan::hex_encode(pt2)<<std::endl;
    std::string plaintext2(reinterpret_cast<const char*>(pt2.data()), pt2.size());
    std::cout<<plaintext2<<std::endl;
   return 0;
}