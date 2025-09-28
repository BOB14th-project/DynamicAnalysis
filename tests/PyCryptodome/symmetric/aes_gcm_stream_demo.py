"""PyCryptodome AES-256-GCM demo with multi-part encryption."""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
nonce = get_random_bytes(12)
segments = [b"multi-part ", b"encryption ", b"with gcm"]

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext_parts = [cipher.encrypt(part) for part in segments]
tag = cipher.digest()

ciphertext = b"".join(ciphertext_parts)
print("ciphertext", ciphertext.hex())
print("tag", tag.hex())

# Multi-part decrypt
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext_parts = [cipher2.decrypt(part) for part in ciphertext_parts]
try:
    cipher2.verify(tag)
    print("verified", b"".join(plaintext_parts).decode())
except ValueError:
    print("verification failed")
