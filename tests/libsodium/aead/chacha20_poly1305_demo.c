// chacha20_poly1305_demo.c
// Minimal libsodium AEAD example using crypto_aead_chacha20poly1305_ietf.
// Exercises encrypt/decrypt and detached variants so the libsodium AEAD hook
// can observe key/nonce/tag material emitted by both code paths.
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
    unsigned long long ciphertext_len = 0;
    const unsigned char message[] = "hello from libsodium";

    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
                                                  message, sizeof message - 1,
                                                  NULL, 0, NULL, nonce, key) != 0) {
        fprintf(stderr, "encrypt failed\n");
        return 1;
    }

    printf("encrypt len=%llu first=0x%02x\n", ciphertext_len, ciphertext[0]);

    unsigned char decrypted[128];
    unsigned long long decrypted_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL,
                                                  ciphertext, ciphertext_len,
                                                  NULL, 0, nonce, key) != 0) {
        fprintf(stderr, "decrypt failed\n");
        return 1;
    }
    decrypted[decrypted_len] = '\0';
    printf("decrypt ok: %s\n", decrypted);

    unsigned char detached_ct[128];
    unsigned char mac[crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long mac_len = 0;

    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(detached_ct, mac, &mac_len,
                                                           message, sizeof message - 1,
                                                           NULL, 0, NULL, nonce, key) != 0) {
        fprintf(stderr, "encrypt_detached failed\n");
        return 1;
    }

    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(decrypted, NULL,
                                                           detached_ct, sizeof message - 1,
                                                           mac, NULL, 0,
                                                           nonce, key) != 0) {
        fprintf(stderr, "decrypt_detached failed\n");
        return 1;
    }

    printf("detached mac first=0x%02x\n", mac[0]);
    return 0;
}
