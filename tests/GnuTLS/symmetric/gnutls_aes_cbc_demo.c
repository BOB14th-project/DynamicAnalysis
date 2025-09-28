// gnutls_aes_cbc_demo.c
// Demonstrates AES-256-CBC encryption/decryption using GnuTLS cipher API.

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <string.h>

static void bail(const char* msg) {
    fprintf(stderr, "%s\n", msg);
}

int main(void) {
    gnutls_datum_t key = {
        .data = (unsigned char*)"abcdef0123456789abcdef0123456789",
        .size = 32,
    };
    unsigned char iv[16] = {
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };
    gnutls_datum_t iv_datum = { .data = iv, .size = sizeof(iv) };

    unsigned char plaintext[32] = {0};
    memcpy(plaintext, "gnutls aes cbc plaintext demo!", 30);
    unsigned char ciphertext[32] = {0};
    unsigned char decrypted[32] = {0};

    gnutls_cipher_hd_t enc = NULL;
    if (gnutls_cipher_init(&enc, GNUTLS_CIPHER_AES_256_CBC, &key, &iv_datum) < 0) {
        bail("cipher init failed");
        return 1;
    }
    if (gnutls_cipher_encrypt2(enc, plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext)) < 0) {
         bail("cipher encrypt2 failed");
         gnutls_cipher_deinit(enc);
         return 1;
    }
    gnutls_cipher_deinit(enc);

    gnutls_cipher_hd_t dec = NULL;
    unsigned char iv_reset[16];
    memcpy(iv_reset, iv, sizeof(iv));
    gnutls_datum_t iv_reset_datum = { .data = iv_reset, .size = sizeof(iv_reset) };
    if (gnutls_cipher_init(&dec, GNUTLS_CIPHER_AES_256_CBC, &key, &iv_reset_datum) < 0) {
        bail("decrypt init failed");
        return 1;
    }
    gnutls_cipher_set_iv(dec, iv_reset, sizeof(iv_reset));
    if (gnutls_cipher_decrypt2(dec, ciphertext, sizeof(ciphertext), decrypted, sizeof(decrypted)) < 0) {
        bail("cipher decrypt2 failed");
        gnutls_cipher_deinit(dec);
        return 1;
    }
    gnutls_cipher_deinit(dec);

    if (memcmp(plaintext, decrypted, sizeof(plaintext)) != 0) {
        bail("plaintext mismatch");
        return 1;
    }

    printf("cbc success: first_ct=0x%02x\n", ciphertext[0]);
    return 0;
}
