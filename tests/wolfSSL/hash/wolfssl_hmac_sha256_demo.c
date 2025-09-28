// wolfssl_hmac_sha256_demo.c
// HMAC-SHA256 example using wolfSSL (wolfCrypt).
// Build:
//   gcc wolfssl_hmac_sha256_demo.c -lwolfssl -o wolfssl_hmac_sha256_demo

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const byte key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const byte message[] = "wolfssl hmac demo";
    byte tag[32] = {0};

    Hmac hmac;
    if (wc_HmacInit(&hmac, NULL, 0) != 0) {
        fprintf(stderr, "wc_HmacInit failed\n");
        return 1;
    }

    if (wc_HmacSetKey(&hmac, WC_SHA256, key, sizeof(key)) != 0) {
        fprintf(stderr, "wc_HmacSetKey failed\n");
        wc_HmacFree(&hmac);
        return 1;
    }

    if (wc_HmacUpdate(&hmac, message, sizeof(message) - 1) != 0) {
        fprintf(stderr, "wc_HmacUpdate failed\n");
        wc_HmacFree(&hmac);
        return 1;
    }

    if (wc_HmacFinal(&hmac, tag) != 0) {
        fprintf(stderr, "wc_HmacFinal failed\n");
        wc_HmacFree(&hmac);
        return 1;
    }

    wc_HmacFree(&hmac);

    printf("hmac first=0x%02x\n", tag[0]);
    return 0;
}
