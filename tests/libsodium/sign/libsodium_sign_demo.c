// libsodium_sign_demo.c
// Exercises libsodium's crypto_sign_detached API to ensure the hook captures
// signing keys and signatures.

#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "crypto_sign_keypair failed\n");
        return 1;
    }

    const unsigned char message[] = "libsodium sign demo";
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long siglen = 0;

    if (crypto_sign_detached(sig, &siglen, message, sizeof(message) - 1, sk) != 0) {
        fprintf(stderr, "crypto_sign_detached failed\n");
        return 1;
    }

    if (crypto_sign_verify_detached(sig, message, sizeof(message) - 1, pk) != 0) {
        fprintf(stderr, "signature verification failed\n");
        return 1;
    }

    printf("libsodium sign demo produced %llu-byte signature\n", siglen);
    return 0;
}
