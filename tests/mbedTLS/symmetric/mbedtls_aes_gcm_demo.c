// mbedtls_aes_gcm_demo.c
// Minimal AES-256-GCM example using Mbed TLS.
// Build (requires mbedtls):
//   gcc mbedtls_aes_gcm_demo.c -lmbedcrypto -o mbedtls_aes_gcm_demo

#include <mbedtls/gcm.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    unsigned char key[32] = {0};
    unsigned char iv[12] = {0};
    const unsigned char plaintext[] = "hello from mbedtls";
    unsigned char ciphertext[64] = {0};
    unsigned char tag[16] = {0};

    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        fprintf(stderr, "setkey failed\n");
        return 1;
    }
    if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
                                  sizeof(plaintext) - 1,
                                  iv, sizeof(iv),
                                  NULL, 0,
                                  plaintext, ciphertext,
                                  sizeof(tag), tag) != 0) {
        fprintf(stderr, "gcm encrypt failed\n");
        mbedtls_gcm_free(&ctx);
        return 1;
    }
    printf("ciphertext first=0x%02x tag0=0x%02x\n", ciphertext[0], tag[0]);

    mbedtls_gcm_free(&ctx);
    return 0;
}
