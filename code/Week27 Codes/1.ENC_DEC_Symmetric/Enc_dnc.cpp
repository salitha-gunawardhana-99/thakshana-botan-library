
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <iostream>
#include <botan/cipher_mode.h>

Botan::AutoSeeded_RNG rng;

//AES-128 Encryption
Botan::secure_vector<uint8_t> AES128_ENC(std::string ptext,std::vector<uint8_t> key,Botan::secure_vector<uint8_t> iv )
{
    const std::string plaintext(ptext);
    const auto enc = Botan::Cipher_Mode::create_or_throw("AES-128/CBC/PKCS7", Botan::Cipher_Dir::Encryption);
    enc->set_key(key);

    
    Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
    enc->start(iv);
    enc->finish(pt);
    std::string cipher_text = Botan::hex_encode(pt);
    return pt;

}

//AES-128 Decryption
std::string AES128_DEC(Botan::secure_vector<uint8_t> ct,std::vector<uint8_t> key,Botan::secure_vector<uint8_t> iv )
{

    const auto dec = Botan::Cipher_Mode::create_or_throw("AES-128/CBC/PKCS7", Botan::Cipher_Dir::Decryption);
    dec->set_key(key); 
    dec->start(iv);
    dec->finish(ct);

    std::string plaintext(reinterpret_cast<const char*>(ct.data()), ct.size());
    return plaintext;


}
int main() {
   
    const size_t length = 16;
    std::vector<uint8_t> key(length);
    std::string message = "Hello World";
    rng.randomize(key.data(),key.size());
    std::cout<<"random_number = "<<key.data()<<std::endl;
    Botan::secure_vector<uint8_t> iv = rng.random_vec(length);
    Botan::secure_vector<uint8_t> cipher_array = AES128_ENC(message,key,iv);
    std::string cipher_output = Botan::hex_encode(cipher_array);
    std::cout<<"the ciphertext is "<<cipher_output<<std::endl;
    std::string decrypt_msg = AES128_DEC(cipher_array,key,iv);
    std::cout<<"decrypted output is "<<decrypt_msg<<std::endl;
    return 0;

}