// boringssl_aes_gcm_demo.cc
// Minimal AES-256-GCM encryption using BoringSSL EVP API.
// Build (requires BoringSSL):
//   clang++ boringssl_aes_gcm_demo.cc -lcrypto -o boringssl_aes_gcm_demo

#include <openssl/aead.h>
#include <openssl/rand.h>
#include <cstdio>
#include <cstring>

int main() {
    uint8_t key[32];
    uint8_t nonce[12];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "hello from boringssl";
    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;

    EVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key, sizeof(key), 16, nullptr)) {
        std::fprintf(stderr, "EVP_AEAD_CTX_init failed\n");
        return 1;
    }
    if (!EVP_AEAD_CTX_seal(&ctx, ciphertext, &ciphertext_len, sizeof(ciphertext),
                           nonce, sizeof(nonce),
                           plaintext, sizeof(plaintext)-1,
                           nullptr, 0)) {
        std::fprintf(stderr, "EVP_AEAD_CTX_seal failed\n");
        EVP_AEAD_CTX_cleanup(&ctx);
        return 1;
    }

    std::printf("ciphertext len=%zu first=0x%02x\n", ciphertext_len, ciphertext[0]);
    EVP_AEAD_CTX_cleanup(&ctx);
    return 0;
}
