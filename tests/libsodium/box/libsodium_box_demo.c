// libsodium_box_demo.c
// Demonstrates crypto_box_easy / crypto_box_open_easy.
// Produces a sender/recipient key exchange to exercise the hook for
// public-key authenticated encryption in libsodium.

#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }

    const unsigned char message[] = "box roundtrip";
    unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sender_sk[crypto_box_SECRETKEYBYTES];
    unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];
    unsigned char nonce[crypto_box_NONCEBYTES];

    if (crypto_box_keypair(sender_pk, sender_sk) != 0 ||
        crypto_box_keypair(recipient_pk, recipient_sk) != 0) {
        fprintf(stderr, "keypair generation failed\n");
        return 1;
    }

    randombytes_buf(nonce, sizeof nonce);

    unsigned char ciphertext[sizeof(message) - 1 + crypto_box_MACBYTES];
    unsigned char decrypted[sizeof(message) - 1 + 1];

    if (crypto_box_easy(ciphertext, message, sizeof(message) - 1, nonce, recipient_pk, sender_sk) != 0) {
        fprintf(stderr, "box encrypt failed\n");
        return 1;
    }

    if (crypto_box_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, sender_pk, recipient_sk) != 0) {
        fprintf(stderr, "box decrypt failed\n");
        return 1;
    }

    decrypted[sizeof(message) - 1] = '\0';
    printf("box ok: %s\n", decrypted);
    return 0;
}
