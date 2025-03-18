#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include <botan/cipher_mode.h>
#include <assert.h>
#include <iostream>

Botan::AutoSeeded_RNG rng;
static std::string compute_mac(const std::string &msg, const Botan::secure_vector<uint8_t> &key)
{
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

    hmac->set_key(key);
    hmac->update(msg);

    return Botan::hex_encode(hmac->final());
}

Botan::secure_vector<uint8_t> AES128_ENC(std::string ptext, Botan::secure_vector<uint8_t> key, Botan::secure_vector<uint8_t> iv)
{
    const std::string plaintext(ptext);
    const auto enc = Botan::Cipher_Mode::create_or_throw("AES-128/GCM", Botan::Cipher_Dir::Encryption);
    enc->set_key(key);

    Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
    enc->start(iv);
    enc->finish(pt);
    std::string cipher_text = Botan::hex_encode(pt);
    // std::cout << enc->name() << " with iv " << Botan::hex_encode(iv) << " " << cipher_text << '\n';
    return pt;
}

std::string AES128_DEC(Botan::secure_vector<uint8_t> ct, Botan::secure_vector<uint8_t> key, Botan::secure_vector<uint8_t> iv)
{

    const auto dec = Botan::Cipher_Mode::create_or_throw("AES-128/GCM", Botan::Cipher_Dir::Decryption);
    dec->set_key(key);

    // std::vector<uint8_t> ct(ctext.length() / 2);
    // size_t decoded_size = Botan::hex_decode(ct.data(), ctext.data(), ctext.length());

    dec->start(iv);
    dec->finish(ct);

    std::string plaintext(reinterpret_cast<const char *>(ct.data()), ct.size());
    return plaintext;
}

int main()
{

    const auto key = rng.random_vec(16); // 128 bit random key
    Botan::secure_vector<uint8_t> key_vect = key;
    std::string message = "This is a very private message";
    const size_t length = 16;

    Botan::secure_vector<uint8_t> iv = rng.random_vec(length);
    Botan::secure_vector<uint8_t> cipher_array = AES128_ENC(message, key_vect, iv);
    std::string cipher_output = Botan::hex_encode(cipher_array);
    // "Message" != "Mussage" so tags will also not match
    std::string alis_tag = compute_mac(cipher_output, key_vect);
    std::string bob_tag = compute_mac(cipher_output, key_vect);
    std::cout << "Alis Mac code = " << alis_tag << std::endl;
    std::cout << "Bob Mac code = " << bob_tag << std::endl;

    if (alis_tag == bob_tag)
    {
        std::string decrypt_msg = AES128_DEC(cipher_array, key, iv);
        std::cout << "decrypted output is: " << decrypt_msg << std::endl;
    }
    else
    {
        std::cout << "The message has been tampered" << std::endl;
    }

    return 0;
}