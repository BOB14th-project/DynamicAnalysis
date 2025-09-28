"""PyCryptodome AES-256-GCM demo with AAD and verification."""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
nonce = get_random_bytes(12)
aad = b"authenticated but not encrypted"
plaintext = b"pycryptodome gcm with aad"

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher.update(aad)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

print("ciphertext", ciphertext.hex())
print("tag", tag.hex())

# Verify by decrypting
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher2.update(aad)
recovered = cipher2.decrypt_and_verify(ciphertext, tag)
print("recovered", recovered.decode())
