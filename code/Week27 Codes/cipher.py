import botan3 as botan

def main():
    message = "Hello, Botan 3!"
    hash = botan.HashFunction('SHA-256')
    hash.update(message.encode('utf-8'))
    digest = hash.final()

    print("Message:", message)
    print("SHA-256 Digest:", digest.hex())

if __name__ == "__main__":
    main()