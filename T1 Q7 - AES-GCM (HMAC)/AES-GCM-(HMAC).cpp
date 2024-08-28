#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include <botan/cipher_mode.h>
#include <iostream>
#include <vector>

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

// Compute HMAC function
std::string compute_mac(const std::string &msg, const Botan::secure_vector<uint8_t> &key)
{
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

    hmac->set_key(key);
    hmac->update(msg);

    return Botan::hex_encode(hmac->final());
}

int main()
{
    Botan::AutoSeeded_RNG rng;

    const size_t key_size = 32; // 256-bit key
    const size_t iv_size = 12;  // Recommended length for AES-GCM IV

    // Generate keys and IV
    const auto key = rng.random_vec(key_size);
    Botan::secure_vector<uint8_t> key_vect = key;
    Botan::secure_vector<uint8_t> iv = rng.random_vec(iv_size);

    std::string message = "This message remains confidential.";

    // Encrypt the message
    Botan::secure_vector<uint8_t> cipher_array = AES256_ENC(message, key_vect, iv);

    // Compute HMAC for the ciphertext
    std::string cipher_output = Botan::hex_encode(cipher_array);
    std::string hmac = compute_mac(cipher_output, key_vect);

    // Print encrypted message and HMAC
    std::cout << "_Encrypted (hex): " << cipher_output << std::endl;
    std::cout << "____________HMAC: " << hmac << std::endl;

    // For demonstration, assume we received the ciphertext and HMAC
    std::string received_cipher_output = cipher_output;
    std::string received_hmac = hmac;

    // Recompute HMAC for received ciphertext
    std::string computed_hmac = compute_mac(received_cipher_output, key_vect);

    // Verify HMAC
    if (computed_hmac == received_hmac)
    {
        // HMAC is valid, proceed with decryption
        std::string decrypted_msg = AES256_DEC(cipher_array, key_vect, iv);
        std::cout << "Decrypted output: " << decrypted_msg + "\n"
                  << std::endl;
    }
    else
    {
        // HMAC is invalid, data may have been tampered with
        std::cout << "The message has been tampered with.\n"
                  << std::endl;
    }

    return 0;
}
