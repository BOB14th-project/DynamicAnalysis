// chacha20_poly1305_demo.c
// Minimal libsodium AEAD example using crypto_aead_chacha20poly1305_ietf.
// Build (requires libsodium):
//   gcc chacha20_poly1305_demo.c -lsodium -o chacha20_poly1305_demo

#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }

    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    unsigned char ciphertext[128];
    unsigned long long ciphertext_len;
    const unsigned char message[] = "hello from libsodium";

    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);

    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
                                              message, sizeof message - 1,
                                              NULL, 0, NULL, nonce, key);

    printf("ciphertext len=%llu first=0x%02x\n", ciphertext_len, ciphertext[0]);
    return 0;
}
