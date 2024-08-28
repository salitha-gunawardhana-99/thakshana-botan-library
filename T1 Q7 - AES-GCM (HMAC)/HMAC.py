import botan3 as botan
import os

def compute_mac(msg: str, key: bytes) -> str:
    # Create HMAC instance
    mac = botan.MsgAuthCode('HMAC(SHA-256)')
    
    # Set the key for the MAC
    mac.set_key(key)
    
    # Update the MAC with the message
    mac.update(msg.encode('utf-8'))
    
    # Finalize and get the MAC tag
    return botan._hex_encode(mac.final())

def main():
    # Create a random number generator instance
    rng = botan.RandomNumberGenerator()
    
    # Generate a 256-bit random key
    key = rng.get(32)  # 32 bytes * 8 = 256 bits

    # Compute HMAC for different messages
    tag1 = compute_mac("Message", key)
    tag2 = compute_mac("Mussage", key)

    # Print the HMAC tags
    print(f"HMAC for 'Message': {tag1}")
    print(f"HMAC for 'Mussage': {tag2}")

    # Check if tags are different
    assert tag1 != tag2, "Tags should be different"
    print("Assertion 1 passed: Tags are different.")

    # Recompute HMAC for the original message
    tag3 = compute_mac("Message", key)

    # Print the recomputed HMAC tag
    print(f"\nHMAC for 'Message': {tag3}")

    # Check if recomputed tag matches the original
    assert tag1 == tag3, "Recomputed tag should match the original"
    print("Assertion 2 passed: Recomputed tag matches the original.\n")

if __name__ == "__main__":
    main()
