"""aes_gcm_demo.py
Minimal AES-256-GCM encryption using PyCryptodome.
Run: python3 aes_gcm_demo.py
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
nonce = get_random_bytes(12)
plaintext = b"hello from pycryptodome"

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

print("ciphertext", ciphertext.hex())
print("tag", tag.hex())
