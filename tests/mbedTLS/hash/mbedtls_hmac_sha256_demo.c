// mbedtls_hmac_sha256_demo.c
// Demonstrates HMAC-SHA256 using Mbed TLS so hooks can observe key usage.

#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        fprintf(stderr, "md_info_from_type failed\n");
        return 1;
    }
    if (mbedtls_md_setup(&ctx, info, 1) != 0) {
        fprintf(stderr, "md_setup failed\n");
        mbedtls_md_free(&ctx);
        return 1;
    }

    unsigned char key[32];
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (unsigned char)(0x30 + i);

    const unsigned char msg[] = "mbedtls hmac demo";
    unsigned char mac[32];

    if (mbedtls_md_hmac_starts(&ctx, key, sizeof(key)) != 0 ||
        mbedtls_md_hmac_update(&ctx, msg, sizeof(msg) - 1) != 0 ||
        mbedtls_md_hmac_finish(&ctx, mac) != 0) {
        fprintf(stderr, "hmac failed\n");
        mbedtls_md_free(&ctx);
        return 1;
    }

    printf("hmac first byte=0x%02x\n", mac[0]);

    mbedtls_md_free(&ctx);
    return 0;
}
