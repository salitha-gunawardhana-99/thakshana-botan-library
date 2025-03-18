#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <iostream>

// Function to encrypt plaintext
std::vector<uint8_t> encrypt(const std::string &plaintext, const Botan::Public_Key &public_key, Botan::AutoSeeded_RNG &rng)
{
    std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
    Botan::PK_Encryptor_EME enc(public_key, rng, "OAEP(SHA-256)");
    return enc.encrypt(pt, rng);
}

// Function to decrypt ciphertext
std::string decrypt(const std::vector<uint8_t> &ciphertext, const Botan::Private_Key &private_key, Botan::AutoSeeded_RNG &rng)
{
    Botan::PK_Decryptor_EME dec(private_key, rng, "OAEP(SHA-256)");
    Botan::secure_vector<uint8_t> pt2 = dec.decrypt(ciphertext);
    return std::string(pt2.begin(), pt2.end());
}

// Function to print hex encoded data
void print_hex(const std::string &label, const std::vector<uint8_t> &data)
{
    std::cout << label << Botan::hex_encode(data) << std::endl;
}

int main()
{
    std::string plaintext("This message is to be encrypted using RSA");
    Botan::AutoSeeded_RNG rng;

    // Load keypair
    std::string pem_file = "rsa_private.pem";
    Botan::DataSource_Stream in(pem_file);
    auto kp = Botan::PKCS8::load_key(in);

    // Separate public and private keys
    const Botan::Private_Key &private_key = dynamic_cast<const Botan::Private_Key &>(*kp);
    const Botan::Public_Key &public_key = dynamic_cast<const Botan::Public_Key &>(*kp);

    // Encrypt plaintext
    std::vector<uint8_t> ciphertext = encrypt(plaintext, public_key, rng);

    // Decrypt ciphertext
    std::string decrypted_text = decrypt(ciphertext, private_key, rng);

    // Print results
    std::cout << "_____Plaintext: " << plaintext << std::endl;
    print_hex("Encrypted text: ", ciphertext);
    std::cout << "Decrypted text: " << decrypted_text + "\n"
              << std::endl;

    return 0;
}
