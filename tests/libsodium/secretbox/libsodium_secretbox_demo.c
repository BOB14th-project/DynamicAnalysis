// libsodium_secretbox_demo.c
// Demonstrates crypto_secretbox_easy / crypto_secretbox_open_easy.
// Intended to validate the libsodium secretbox hook by generating a
// round-trip that exposes the key and nonce used for the detached MAC.

#include <sodium.h>
#include <stdio.h>

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }

    const unsigned char message[] = "secretbox roundtrip";
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    unsigned char ciphertext[sizeof(message) - 1 + crypto_secretbox_MACBYTES];
    unsigned char decrypted[sizeof(message) - 1 + 1];

    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_secretbox_easy(ciphertext, message, sizeof(message) - 1, nonce, key) != 0) {
        fprintf(stderr, "secretbox encrypt failed\n");
        return 1;
    }

    if (crypto_secretbox_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, key) != 0) {
        fprintf(stderr, "secretbox decrypt failed\n");
        return 1;
    }

    decrypted[sizeof(message) - 1] = '\0';
    printf("secretbox ok: %s\n", decrypted);
    return 0;
}
