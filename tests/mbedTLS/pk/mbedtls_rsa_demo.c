// mbedtls_rsa_demo.c
// Uses a fixed RSA private key to sign a message via mbedtls_pk_sign.

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <string.h>

static const char kRsaKeyPem[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALMfPTVpjdjuaoJ+\n"
"C6jRWF0Mb08MJArnV4HLDTuuc4LZ/fGcz6ER967DgAV8Z7X1cRR8tJDKS+GPZawq\n"
"T1FC4eH3iZ2AqW7iDu1khnH4yh7/G0qthhAcV6l51KZqBZs51qBCg0MEa5n/N0kE\n"
"uIyQgE/irNTTmt8atYH4DiFh68/dAgMBAAECgYBpk2wcY068IiqdJ3Xv1xRiI8Yn\n"
"rVxBIQIu+mOeXcCvy5UmJ+spYNHALHL0yNLIKRaxoJ89CD+Zf0/KHlYJ64X/EX+f\n"
"NqxE7B/jStKO5dcNyYnMs8SOHBSnQgR6tSgVNPzUU7a8oT4/doic1wImfkaiaHpT\n"
"Vo/XNZPc9558ERb+gQJBAOH4G+bLyBQS/AG1eiBAUITh0/V9MWWAMsuc/xPWav2f\n"
"an/OEnDSB79QsgsfBlz36RltPiB+cAWJjpOEhMLbyPUCQQDK7U2Z5VDAwCsa7/j7\n"
"rTm0GNDknWpcX6wvX06FD4wVLjbzLERhDdzeNq2rYKbiaDAu07lDCQs9SU5gPyY7\n"
"2DpJAkEAso5lLchU/1fI/miyag2oEniIDnGwuK3GdZJHFRvXSzXO59KkS7YLHSfc\n"
"qGEJnCjhbpAeCXsfdaCuou6SIY+eiQJAeWMYb32oH5UUc+mms848XUoW8xpi/FzS\n"
"oAfP7XKOZkEd57rMMI5dV6O3oXOQgJC4edp20O3BBmkqdBJyaYv/2QJBANgncodO\n"
"MCKgjMyXmkYGMEJVE+e5mkndwQlqk67XEUfsX1/QbBWABSHH+wxqeLRS1vZNHFkN\n"
"WWQuStmWhjCPp/w=\n"
"-----END PRIVATE KEY-----\n";

int main(void) {
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;
    int ret = 0;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);

    const char* pers = "mbedtls_rsa_demo";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers)) != 0) {
        fprintf(stderr, "ctr_drbg_seed failed\n");
        goto cleanup;
    }

    ret = mbedtls_pk_parse_key(&pk,
                               (const unsigned char*)kRsaKeyPem,
                               strlen(kRsaKeyPem) + 1,
                               NULL,
                               0);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        fprintf(stderr, "pk_parse_key failed: -0x%04x - %s\n", -ret, err_buf);
        goto cleanup;
    }

    const unsigned char message[] = "mbedtls rsa demo";
    unsigned char hash[32];
    ret = mbedtls_sha256_ret(message, sizeof(message) - 1, hash, 0);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        fprintf(stderr, "sha256 failed: -0x%04x - %s\n", -ret, err_buf);
        goto cleanup;
    }

    unsigned char sig[256];
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

    printf("mbedtls rsa demo produced %zu-byte signature\n", sig_len);

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    return 0;
}
