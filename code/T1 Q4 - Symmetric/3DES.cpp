#include <botan/block_cipher.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <iostream>

// Function to print data as hexadecimal
void print_hex(const std::string &label, const std::vector<uint8_t> &data)
{
    std::cout << '\n'
              << label << ": " << Botan::hex_encode(data);
}

// Function to convert a string to a vector of bytes
std::vector<uint8_t> string_to_bytes(const std::string &str)
{
    return std::vector<uint8_t>(str.begin(), str.end());
}

// Function to convert a vector of bytes to a string
std::string bytes_to_string(const std::vector<uint8_t> &bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

// Function to perform encryption
std::vector<uint8_t> encrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext)
{
    std::vector<uint8_t> ciphertext;
    try
    {
        // Create a 3DES cipher object
        auto cipher = Botan::BlockCipher::create("TripleDES");
        if (!cipher)
        {
            throw std::runtime_error("Failed to create cipher.");
        }

        print_hex(cipher->name() + " ____plain text", plaintext);

        cipher->set_key(key);

        // Encrypt the block
        ciphertext = plaintext; // Copy plaintext to ciphertext vector
        cipher->encrypt(ciphertext);
        print_hex(cipher->name() + " encrypted text", ciphertext);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Encryption error: " << e.what() << '\n';
    }
    return ciphertext;
}

// Function to perform decryption
std::vector<uint8_t> decrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext)
{
    std::vector<uint8_t> decryptedtext;
    try
    {
        // Create a 3DES cipher object
        auto cipher = Botan::BlockCipher::create("TripleDES");
        if (!cipher)
        {
            throw std::runtime_error("Failed to create cipher.");
        }

        cipher->set_key(key);

        // Decrypt the block
        decryptedtext = ciphertext; // Copy ciphertext to decryptedtext vector
        cipher->decrypt(decryptedtext);
        print_hex(cipher->name() + " decrypted text", decryptedtext);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Decryption error: " << e.what() << '\n';
    }
    return decryptedtext;
}

int main()
{
    Botan::AutoSeeded_RNG rng;

    // Generate a random key for 3DES (192 bits = 24 bytes)
    Botan::secure_vector<uint8_t> secure_key = rng.random_vec(24);
    std::vector<uint8_t> key(secure_key.begin(), secure_key.end());
    std::cout << "Generated Key: " << Botan::hex_encode(key) << std::endl;

    // The human-readable message to be encrypted
    std::string message = "This message is to be encrypted using TripleDES";

    // Convert the message to a vector of bytes
    std::vector<uint8_t> plaintext = string_to_bytes(message);

    // Perform encryption
    std::vector<uint8_t> ciphertext = encrypt(key, plaintext);

    // Perform decryption
    std::vector<uint8_t> decryptedtext = decrypt(key, ciphertext);

    // Convert the decrypted text back to a string
    std::string decrypted_message = bytes_to_string(decryptedtext);

    // Verify decryption matches original message
    if (decrypted_message == message)
    {
        std::cout << "\n\nReceived message: " + message;
        std::cout << "\nDecryption successful, message matches.\n\n";
    }
    else
    {
        std::cout << "\nDecryption failed, message does not match.\n\n";
    }

    return 0;
}
