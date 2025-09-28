// gnutls_aes_gcm_demo.c
// Minimal AES-256-GCM encryption using GnuTLS crypto API.
// Build (requires libgnutls):
//   gcc gnutls_aes_gcm_demo.c -lgnutls -o gnutls_aes_gcm_demo

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    gnutls_datum_t key = { .data = (unsigned char*)"0123456789abcdef0123456789abcdef", .size = 32 };
    unsigned char iv[12] = {0};
    gnutls_datum_t iv_datum = { .data = iv, .size = sizeof(iv) };
    unsigned char tag[16];
    const unsigned char* msg = (const unsigned char*)"hello from gnutls";
    size_t msg_len = strlen((const char*)msg);
    unsigned char out[64] = {0};

    gnutls_cipher_hd_t handle;
    if (gnutls_cipher_init(&handle, GNUTLS_CIPHER_AES_256_GCM, &key, &iv_datum) < 0) {
        fprintf(stderr, "cipher init failed\n");
        return 1;
    }
    if (gnutls_cipher_add_auth(handle, msg, msg_len) < 0) {
        fprintf(stderr, "cipher add auth failed\n");
        gnutls_cipher_deinit(handle);
        return 1;
    }
    if (gnutls_cipher_encrypt2(handle, msg, msg_len, out, msg_len) < 0) {
        fprintf(stderr, "cipher encrypt failed\n");
        gnutls_cipher_deinit(handle);
        return 1;
    }
    if (gnutls_cipher_tag(handle, tag, sizeof(tag)) < 0) {
        fprintf(stderr, "cipher tag failed\n");
        gnutls_cipher_deinit(handle);
        return 1;
    }

    printf("ciphertext len=%zu first=0x%02x tag0=0x%02x\n", msg_len, out[0], tag[0]);

    gnutls_cipher_deinit(handle);
    return 0;
}
