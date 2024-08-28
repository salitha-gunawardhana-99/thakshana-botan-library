#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/cipher_mode.h>
#include <iostream>

Botan::AutoSeeded_RNG rng;

// Encryption function
Botan::secure_vector<uint8_t> AES256_ENC(const std::string &ptext, const Botan::secure_vector<uint8_t> &key, const Botan::secure_vector<uint8_t> &iv)
{
    const auto enc = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    enc->set_key(key);

    Botan::secure_vector<uint8_t> pt(ptext.data(), ptext.data() + ptext.size());
    enc->start(iv);
    enc->finish(pt);

    return pt;
}

// Decryption function
std::string AES256_DEC(const Botan::secure_vector<uint8_t> &ct, const Botan::secure_vector<uint8_t> &key, const Botan::secure_vector<uint8_t> &iv)
{
    const auto dec = Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    dec->set_key(key);

    Botan::secure_vector<uint8_t> decrypted(ct); // Copy ciphertext for decryption
    dec->start(iv);
    dec->finish(decrypted);

    return std::string(reinterpret_cast<const char *>(decrypted.data()), decrypted.size());
}

int main()
{
    const auto key = rng.random_vec(32); // 256-bit random key
    Botan::secure_vector<uint8_t> key_vect = key;
    std::string message = "This is a very private message";
    const size_t length = 12; // Recommended length for AES-GCM IV

    Botan::secure_vector<uint8_t> iv = rng.random_vec(length);

    // Encrypt the message
    Botan::secure_vector<uint8_t> cipher_array = AES256_ENC(message, key_vect, iv);
    std::string cipher_output = Botan::hex_encode(cipher_array);
    std::cout << "_Encrypted (hex): " << cipher_output << std::endl;

    // Decrypt the message
    std::string decrypted_msg = AES256_DEC(cipher_array, key_vect, iv);
    std::cout << "Decrypted output: " << decrypted_msg << std::endl;

    return 0;
}
