// boringssl_aes_gcm_roundtrip_demo.cc
// AES-256-GCM encrypt/decrypt example using BoringSSL EVP AEAD API.
// Build (requires shared BoringSSL build):
//   clang++ boringssl_aes_gcm_roundtrip_demo.cc -lcrypto -o boringssl_aes_gcm_roundtrip_demo

#include <openssl/aead.h>
#include <openssl/rand.h>

#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    uint8_t key[32];
    uint8_t nonce[12];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));

    const uint8_t plaintext[] = "boringssl aes gcm roundtrip";
    std::vector<uint8_t> ciphertext(sizeof(plaintext) + 16);
    size_t ciphertext_len = 0;

    EVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(&ctx, EVP_aead_aes_256_gcm(), key, sizeof(key), 16, nullptr)) {
        std::fprintf(stderr, "EVP_AEAD_CTX_init failed\n");
        return 1;
    }

    if (!EVP_AEAD_CTX_seal(&ctx,
                           ciphertext.data(), &ciphertext_len, ciphertext.size(),
                           nonce, sizeof(nonce),
                           plaintext, sizeof(plaintext) - 1,
                           nullptr, 0)) {
        std::fprintf(stderr, "EVP_AEAD_CTX_seal failed\n");
        EVP_AEAD_CTX_cleanup(&ctx);
        return 1;
    }

    std::vector<uint8_t> recovered(sizeof(plaintext));
    size_t recovered_len = 0;
    if (!EVP_AEAD_CTX_open(&ctx,
                           recovered.data(), &recovered_len, recovered.size(),
                           nonce, sizeof(nonce),
                           ciphertext.data(), ciphertext_len,
                           nullptr, 0)) {
        std::fprintf(stderr, "EVP_AEAD_CTX_open failed\n");
        EVP_AEAD_CTX_cleanup(&ctx);
        return 1;
    }
    EVP_AEAD_CTX_cleanup(&ctx);

    recovered.resize(recovered_len);
    std::printf("enc_len=%zu dec_ok=%d first_ct=0x%02x\n",
                ciphertext_len,
                std::memcmp(recovered.data(), plaintext, sizeof(plaintext) - 1) == 0,
                ciphertext[0]);
    return 0;
}

