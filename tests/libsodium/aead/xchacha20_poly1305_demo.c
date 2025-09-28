// xchacha20_poly1305_demo.c
// libsodium AEAD example exercising XChaCha20-Poly1305 IETF APIs.
// The goal is to trigger encrypt/decrypt (attached + detached) so the
// libsodium hook captures XChaCha key/nonce/tag values.

#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }

    const unsigned char message[] = "xchacha20-poly1305 roundtrip";
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    unsigned char ciphertext[256];
    unsigned long long ciphertext_len = 0;

    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
                                                   message, sizeof message - 1,
                                                   NULL, 0, NULL, nonce, key) != 0) {
        fprintf(stderr, "xchacha encrypt failed\n");
        return 1;
    }

    unsigned char decrypted[256];
    unsigned long long decrypted_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL,
                                                   ciphertext, ciphertext_len,
                                                   NULL, 0, nonce, key) != 0) {
        fprintf(stderr, "xchacha decrypt failed\n");
        return 1;
    }

    unsigned char mac[crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char detached_ct[256];
    unsigned long long mac_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(detached_ct, mac, &mac_len,
                                                            message, sizeof message - 1,
                                                            NULL, 0, NULL, nonce, key) != 0) {
        fprintf(stderr, "xchacha encrypt_detached failed\n");
        return 1;
    }

    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(decrypted, NULL,
                                                            detached_ct, sizeof message - 1,
                                                            mac, NULL, 0,
                                                            nonce, key) != 0) {
        fprintf(stderr, "xchacha decrypt_detached failed\n");
        return 1;
    }

    printf("xchacha mac first=0x%02x\n", mac[0]);
    return 0;
}
