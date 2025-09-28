// boringssl_chacha20_poly1305_demo.cc
// ChaCha20-Poly1305 encryption example using BoringSSL EVP AEAD API.
// Build (requires shared BoringSSL build):
//   clang++ boringssl_chacha20_poly1305_demo.cc -lcrypto -o boringssl_chacha20_poly1305_demo

#include <openssl/aead.h>
#include <openssl/rand.h>

#include <cstdio>
#include <cstring>

int main() {
    uint8_t key[32];
    uint8_t nonce[12];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "boringssl chacha20 poly1305";
    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;

    EVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_chacha20_poly1305(), key, sizeof(key), 16, nullptr)) {
        std::fprintf(stderr, "EVP_AEAD_CTX_init failed\n");
        return 1;
    }

    if (!EVP_AEAD_CTX_seal(&ctx,
                           ciphertext, &ciphertext_len, sizeof(ciphertext),
                           nonce, sizeof(nonce),
                           plaintext, sizeof(plaintext) - 1,
                           nullptr, 0)) {
        std::fprintf(stderr, "EVP_AEAD_CTX_seal failed\n");
        EVP_AEAD_CTX_cleanup(&ctx);
        return 1;
    }

    EVP_AEAD_CTX_cleanup(&ctx);
    std::printf("ct_len=%zu first=0x%02x\n", ciphertext_len, ciphertext[0]);
    return 0;
}

