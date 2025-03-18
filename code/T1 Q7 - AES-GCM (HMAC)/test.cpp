#include <iostream>
#include <botan/hex.h>
#include <botan/cipher_mode.h>

// Botan::AutoSeeded_RNG rng;

// AES-128 Encryption
void AES128_ENC(std::string key, std::string nonce)
{

    std::unique_ptr<Botan::Cipher_Mode> aes = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);

    aes->set_key(Botan::hex_decode(key));
    const std::vector<uint8_t> iv_n = Botan::hex_decode(nonce);
    std::cout << "hbdsuhds" << std::endl;
    aes->start(iv_n);

    std::string initData = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    std::vector<uint8_t> ct = Botan::hex_decode(initData);
    aes->finish(ct);
    std::string pt = Botan::hex_encode(ct);
    std::cout << pt << std::endl;
}

// AES-128 Decryption
//  std::string AES128_DEC(Botan::secure_vector<uint8_t> ct,std::vector<uint8_t> key,Botan::secure_vector<uint8_t> iv )
//  {

//     const auto dec = Botan::Cipher_Mode::create_or_throw("AES-256/CTR-BE", Botan::Cipher_Dir::Decryption);
//     dec->set_key(key);
//     dec->start(iv);
//     dec->finish(ct);

//     std::string plaintext(reinterpret_cast<const char*>(ct.data()), ct.size());
//     return plaintext;

// }
int main()
{

    // const size_t length = 16;
    // //std::vector<uint8_t> key(length);
    // std::string message = "Hello World";
    std::string key = "3F7907D7BB7065ADAE9DA51B6D0C0D500F8C83C787C3510BD4D2EF06250C6688";
    // //rng.randomize(key.data(),key.size());
    // std::cout<<"random_number = "<<key.data()<<std::endl;
    std::string iv = "48D48E304B151DCFEED068F4";
    // Botan::secure_vector<uint8_t> iv = rng.random_vec(length);
    // Botan::secure_vector<uint8_t> cipher_array = AES128_ENC(message,key,iv);
    // std::string cipher_output = Botan::hex_encode(cipher_array);
    // std::cout<<"the ciphertext is "<<cipher_output<<std::endl;
    // std::string decrypt_msg = AES128_DEC(cipher_array,key,iv);
    // std::cout<<"decrypted output is "<<decrypt_msg<<std::endl;
    std::cout << "testing botan\n";
    AES128_ENC(key, iv);

    return 0;
}