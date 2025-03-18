// Purpose: Kyber is a key encapsulation mechanism (KEM) used for securely exchanging symmetric keys.

#include <botan/kyber.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>
#include <botan/aead.h>
#include <array>
#include <iostream>

int main()
{
    const size_t shared_key_len = 32;
    const std::string kdf = "HKDF(SHA-512)";
    const std::string aead_algo = "AES-256/GCM";

    Botan::System_RNG rng;

    std::array<uint8_t, 16> salt;
    rng.randomize(salt);

    // Generate Kyber key pair
    Botan::Kyber_PrivateKey priv_key(rng, Botan::KyberMode::Kyber512_R3);
    auto pub_key = priv_key.public_key();

    // Encryptor setup
    Botan::PK_KEM_Encryptor enc(*pub_key, kdf);
    const auto kem_result = enc.encrypt(rng, shared_key_len, salt);

    // Decryptor setup
    Botan::PK_KEM_Decryptor dec(priv_key, rng, kdf);
    auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);

    if (dec_shared_key != kem_result.shared_key())
    {
        std::cerr << "Shared keys differ\n";
        return 1;
    }

    // Shared key to be used for AES encryption
    Botan::secure_vector<uint8_t> shared_key = kem_result.shared_key();

    // Example message to encrypt
    std::string plaintext = "This is a secret message.";

    // AEAD encryption
    std::unique_ptr<Botan::AEAD_Mode> encryptor = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    encryptor->set_key(shared_key);
    encryptor->start(salt);

    Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.size());
    encryptor->finish(pt);

    std::cout << "_Encrypted (hex): ";
    for (auto c : pt)
    {
        std::cout << std::hex << static_cast<int>(c);
    }
    std::cout << std::endl;

    // AEAD decryption
    std::unique_ptr<Botan::AEAD_Mode> decryptor = Botan::AEAD_Mode::create(aead_algo, Botan::Cipher_Dir::Decryption);
    decryptor->set_key(shared_key);
    decryptor->start(salt);

    decryptor->finish(pt);

    std::string decrypted_text(reinterpret_cast<const char *>(pt.data()), pt.size());
    std::cout << "Decrypted output: " << decrypted_text << std::endl;

    return 0;
}
