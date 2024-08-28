#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include <assert.h>
#include <iostream> // Include iostream for print statements

namespace
{

   std::string compute_mac(const std::string &msg, const Botan::secure_vector<uint8_t> &key)
   {
      auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

      hmac->set_key(key);
      hmac->update(msg);

      return Botan::hex_encode(hmac->final());
   }

} // namespace

int main()
{
   Botan::AutoSeeded_RNG rng;

   const auto key = rng.random_vec(32); // 256 bit random key

   // Compute HMAC for different messages
   std::string tag1 = compute_mac("Message", key);
   std::string tag2 = compute_mac("Mussage", key);

   // Print the HMAC tags
   std::cout << "HMAC for 'Message': " << tag1 << std::endl;
   std::cout << "HMAC for 'Mussage': " << tag2 << std::endl;

   // Check if tags are different
   assert(tag1 != tag2);
   std::cout << "Assertion 1 passed: Tags are different." << std::endl;

   // Recompute HMAC for the original message
   std::string tag3 = compute_mac("Message", key);

   // Print the recomputed HMAC tag
   std::cout << "\nHMAC for 'Message': " << tag3 << std::endl;

   // Check if recomputed tag matches the original
   assert(tag1 == tag3);
   std::cout << "Assertion 2 passed: Recomputed tag matches the original.\n"
             << std::endl;

   return 0;
}
