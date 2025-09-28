// mbedtls_ecdsa_demo.c
// Uses a hard-coded P-256 private key to sign a message via mbedtls_pk_sign.

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>

static const char kEcdsaKeyPem[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfoESAskuUb/M04Ct\n"
"mkUSLbkY3XKKEt2FHrY29/6iX1ihRANCAASpm5S1tS/LicRG6EfiwLZaFEFiU0zM\n"
"hmfRncaO33xlcuORLVaBF8w7fORZKNXCDIVLNF1Sg6d8w9QlZNZp1Lkh\n"
"-----END PRIVATE KEY-----\n";

int main(void) {
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;
    int ret = 0;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);

    const char* pers = "mbedtls_ecdsa_demo";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers)) != 0) {
        fprintf(stderr, "ctr_drbg_seed failed\n");
        goto cleanup;
    }

    ret = mbedtls_pk_parse_key(&pk,
                               (const unsigned char*)kEcdsaKeyPem,
                               strlen(kEcdsaKeyPem) + 1,
                               NULL,
                               0);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        fprintf(stderr, "pk_parse_key failed: -0x%04x - %s\n", -ret, err_buf);
        goto cleanup;
    }

    const unsigned char message[] = "mbedtls ecdsa demo";
    unsigned char hash[32];
    ret = mbedtls_sha256_ret(message, sizeof(message) - 1, hash, 0);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        fprintf(stderr, "sha256 failed: -0x%04x - %s\n", -ret, err_buf);
        goto cleanup;
    }

    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = 0;
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
                          hash, sizeof(hash),
                          sig, &sig_len,
                          mbedtls_ctr_drbg_random, &ctr);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        fprintf(stderr, "pk_sign failed: -0x%04x - %s\n", -ret, err_buf);
        goto cleanup;
    }

    printf("mbedtls ecdsa demo produced %zu-byte signature\n", sig_len);

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    return 0;
}
