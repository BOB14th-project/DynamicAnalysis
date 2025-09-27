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
    unsigned char tag[16];
    const char* msg = "hello from gnutls";
    unsigned char out[64];
    size_t out_len = 0;

    gnutls_cipher_hd_t handle;
    if (gnutls_cipher_init(&handle, GNUTLS_CIPHER_AES_256_GCM, &key, &key) < 0) {
        fprintf(stderr, "cipher init failed\n");
        return 1;
    }
    gnutls_cipher_add_auth(handle, (const unsigned char*)msg, strlen(msg));
    gnutls_cipher_encrypt(handle, (const unsigned char*)msg, out, strlen(msg));
    gnutls_cipher_tag(handle, tag, sizeof(tag));

    out_len = strlen(msg);
    printf("ciphertext len=%zu first=0x%02x tag0=0x%02x\n", out_len, out[0], tag[0]);

    gnutls_cipher_deinit(handle);
    return 0;
}
