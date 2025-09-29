#pragma once

#include <openssl/evp.h>
#include <vector>
#include <string>

struct OpenSSLState {
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    std::string cipher_name;
};

void openssl_state_remember(EVP_CIPHER_CTX* ctx,
                            const char* cipher_name,
                            const unsigned char* key,
                            size_t key_len,
                            const unsigned char* iv,
                            size_t iv_len);

void openssl_state_remember_key(EVP_CIPHER_CTX* ctx,
                                const char* cipher_name,
                                const unsigned char* key,
                                size_t key_len);

void openssl_state_remember_iv(EVP_CIPHER_CTX* ctx,
                               const char* cipher_name,
                               const unsigned char* iv,
                               size_t iv_len);

bool openssl_state_lookup(const EVP_CIPHER_CTX* ctx, OpenSSLState& out);

void openssl_state_forget(const EVP_CIPHER_CTX* ctx);