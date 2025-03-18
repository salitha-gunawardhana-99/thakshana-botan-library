#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/rsa.h>
#include <iostream>

int main()
{
    std::string plaintext("This message is to be encrypted using RSA");
    std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
    Botan::AutoSeeded_RNG rng;

    try
    {
        // Generate RSA key pair
        Botan::RSA_PrivateKey rsa_private_key(rng, 2048);
        const Botan::RSA_PublicKey &rsa_public_key = rsa_private_key;

        // Encrypt with public key
        Botan::PK_Encryptor_EME enc(rsa_public_key, rng, "OAEP(SHA-256)");
        std::vector<uint8_t> ct = enc.encrypt(pt, rng);

        // Decrypt with private key
        Botan::PK_Decryptor_EME dec(rsa_private_key, rng, "OAEP(SHA-256)");
        Botan::secure_vector<uint8_t> pt2 = dec.decrypt(ct);

        // Print results
        std::cout << "Encrypted: " << Botan::hex_encode(ct) << "\n";
        std::cout << "Decrypted: " << Botan::hex_encode(pt2) << "\n";
        std::string decrypted_text(reinterpret_cast<const char *>(pt2.data()), pt2.size());
        std::cout << "Decrypted text: " << decrypted_text << "\n";
    }
    catch (const Botan::Exception &e)
    {
        std::cerr << "Botan Exception: " << e.what() << "\n";
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Standard Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
