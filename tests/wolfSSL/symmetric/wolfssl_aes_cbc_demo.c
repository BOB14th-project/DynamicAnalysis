// wolfssl_aes_cbc_demo.c
// AES-256-CBC encrypt/decrypt using wolfSSL (wolfCrypt).
// Build (requires wolfSSL):
//   gcc wolfssl_aes_cbc_demo.c -lwolfssl -o wolfssl_aes_cbc_demo

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const byte key[32] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
    byte iv_init[AES_BLOCK_SIZE] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
    };

    const byte plaintext[32] = "wolfssl aes cbc plaintext";
    byte ciphertext[32] = {0};
    byte recovered[32] = {0};

    Aes aesEnc;
    Aes aesDec;

    byte encIv[AES_BLOCK_SIZE];
    memcpy(encIv, iv_init, sizeof(encIv));
    if (wc_AesSetKey(&aesEnc, key, sizeof(key), encIv, AES_ENCRYPTION) != 0) {
        fprintf(stderr, "wc_AesSetKey (enc) failed\n");
        return 1;
    }
    byte decIv[AES_BLOCK_SIZE];
    memcpy(decIv, iv_init, sizeof(decIv));
    if (wc_AesSetKey(&aesDec, key, sizeof(key), decIv, AES_DECRYPTION) != 0) {
        fprintf(stderr, "wc_AesSetKey (dec) failed\n");
        return 1;
    }

    if (wc_AesCbcEncrypt(&aesEnc, ciphertext, plaintext, sizeof(ciphertext)) != 0) {
        fprintf(stderr, "wc_AesCbcEncrypt failed\n");
        return 1;
    }

    // Reset IV for decrypt side
    if (wc_AesSetIV(&aesDec, iv_init) != 0) {
        fprintf(stderr, "wc_AesSetIV failed\n");
        return 1;
    }

    if (wc_AesCbcDecrypt(&aesDec, recovered, ciphertext, sizeof(ciphertext)) != 0) {
        fprintf(stderr, "wc_AesCbcDecrypt failed\n");
        return 1;
    }

    printf("cbc first=0x%02x\n", ciphertext[0]);
    return 0;
}
