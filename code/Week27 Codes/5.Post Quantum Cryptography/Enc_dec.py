import botan3 as botan
import os

rng = botan.RandomNumberGenerator()
#Kyber key generation
kyber_privat_key=botan.PrivateKey.create('Kyber','Kyber-512-r3',rng)
kyber_public_key = kyber_privat_key.get_public_key()
kdf = "HKDF(SHA-512)"
salt = os.urandom(16)
#Key encapsulation
enc = botan.KemEncrypt(kyber_public_key,kdf)
kem_shared,encapped_key = enc.create_shared_key(rng,salt,32)
#Key decapsulation
dec = botan.KemDecrypt(kyber_privat_key,kdf)
dec_shared = dec.decrypt_shared_key(salt,32,encapped_key)
print(dec_shared.hex())
print(kem_shared.hex())
