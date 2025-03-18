import botan3

def hex_decode(hex_string):
    return bytes.fromhex(hex_string)

def hex_encode(byte_data):
    return byte_data.hex().upper()

def main():
    key = hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    block = hex_decode("00112233445566778899AABBCCDDEEFF")
    
    cipher = botan3.BlockCipher("AES-256")
    cipher.set_key(key)
    cipher.encrypt(block)
    print(f"Single block encrypt: {hex_encode(block)}")

if __name__ == "__main__":
    main()
