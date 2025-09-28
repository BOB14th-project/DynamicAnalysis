// gnutls_aes_gcm_roundtrip_demo.c
// Performs AES-256-GCM encryption followed by authenticated decryption using GnuTLS.

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <string.h>

static void bail(const char* msg) {
    fprintf(stderr, "%s\n", msg);
}

int main(void) {
    gnutls_datum_t key = {
        .data = (unsigned char*)"0123456789abcdef0123456789abcdef",
        .size = 32,
    };
    unsigned char iv[12] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    gnutls_datum_t iv_datum = { .data = iv, .size = sizeof(iv) };

    const unsigned char plaintext[] = "gnutls aes gcm roundtrip";
    const unsigned char aad[] = "demo aad";
    const size_t pt_len = strlen((const char*)plaintext);

    unsigned char ciphertext[64] = {0};
    unsigned char recovered[64] = {0};
    unsigned char tag[16] = {0};
    unsigned char verify_tag[16] = {0};

    gnutls_cipher_hd_t enc = NULL;
    if (gnutls_cipher_init(&enc, GNUTLS_CIPHER_AES_256_GCM, &key, &iv_datum) < 0) {
        bail("cipher init failed");
        return 1;
    }
    if (gnutls_cipher_add_auth(enc, aad, sizeof(aad) - 1) < 0) {
        bail("cipher add auth failed");
        gnutls_cipher_deinit(enc);
        return 1;
    }
    if (gnutls_cipher_encrypt2(enc, plaintext, pt_len, ciphertext, pt_len) < 0) {
        bail("cipher encrypt failed");
        gnutls_cipher_deinit(enc);
        return 1;
    }
    if (gnutls_cipher_tag(enc, tag, sizeof(tag)) < 0) {
        bail("cipher tag failed");
        gnutls_cipher_deinit(enc);
        return 1;
    }
    gnutls_cipher_deinit(enc);

    gnutls_cipher_hd_t dec = NULL;
    iv_datum.data = iv;
    iv_datum.size = sizeof(iv);
    if (gnutls_cipher_init(&dec, GNUTLS_CIPHER_AES_256_GCM, &key, &iv_datum) < 0) {
        bail("decrypt init failed");
        return 1;
    }
    if (gnutls_cipher_add_auth(dec, aad, sizeof(aad) - 1) < 0) {
        bail("decrypt add auth failed");
        gnutls_cipher_deinit(dec);
        return 1;
    }
    if (gnutls_cipher_decrypt2(dec, ciphertext, pt_len, recovered, pt_len) < 0) {
        bail("cipher decrypt failed");
        gnutls_cipher_deinit(dec);
        return 1;
    }
    if (gnutls_cipher_tag(dec, verify_tag, sizeof(verify_tag)) < 0) {
        bail("cipher tag check failed");
        gnutls_cipher_deinit(dec);
        return 1;
    }
    if (memcmp(tag, verify_tag, sizeof(tag)) != 0) {
        bail("tag mismatch");
        gnutls_cipher_deinit(dec);
        return 1;
    }
    gnutls_cipher_deinit(dec);

    if (memcmp(recovered, plaintext, pt_len) != 0) {
        bail("plaintext mismatch");
        return 1;
    }

    printf("roundtrip success: first_ct=0x%02x tag0=0x%02x\n", ciphertext[0], tag[0]);
    return 0;
}
