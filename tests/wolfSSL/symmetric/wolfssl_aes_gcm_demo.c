// wolfssl_aes_gcm_demo.c
// Minimal AES-256-GCM example using wolfSSL (wolfCrypt).
// Build (requires wolfssl):
//   gcc wolfssl_aes_gcm_demo.c -lwolfssl -o wolfssl_aes_gcm_demo

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    word32 key[8] = {0};
    byte iv[12] = {0};
    Aes aes;

    const byte plaintext[] = "hello from wolfssl";
    byte ciphertext[64] = {0};
    byte authTag[16] = {0};
    byte aad[1] = {0};

    if (wc_AesGcmSetKey(&aes, (const byte*)key, sizeof(key)) != 0) {
        fprintf(stderr, "wc_AesGcmSetKey failed\n");
        return 1;
    }
    if (wc_AesGcmEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext) - 1,
                         iv, sizeof(iv), authTag, sizeof(authTag), aad, 0) != 0) {
        fprintf(stderr, "wc_AesGcmEncrypt failed\n");
        return 1;
    }
    printf("ciphertext first=0x%02x tag0=0x%02x\n", ciphertext[0], authTag[0]);
    return 0;
}
