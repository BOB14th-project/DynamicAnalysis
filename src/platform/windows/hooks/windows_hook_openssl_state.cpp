// Windows version of OpenSSL state management
// Copied from Linux implementation for cross-platform compatibility

#include "common/pch.h"
#include "common/hook_openssl_state.h"

#include <unordered_map>
#include <mutex>

static std::unordered_map<const EVP_CIPHER_CTX*, OpenSSLState> ctx_state_map;
static std::mutex state_mutex;

void openssl_state_remember(EVP_CIPHER_CTX* ctx,
                            const char* cipher_name,
                            const unsigned char* key,
                            size_t key_len,
                            const unsigned char* iv,
                            size_t iv_len)
{
    if (!ctx) return;

    std::lock_guard<std::mutex> lock(state_mutex);
    OpenSSLState& state = ctx_state_map[ctx];

    if (cipher_name) {
        state.cipher_name = cipher_name;
    }

    if (key && key_len > 0) {
        state.key.assign(key, key + key_len);
    }

    if (iv && iv_len > 0) {
        state.iv.assign(iv, iv + iv_len);
    }
}

void openssl_state_remember_key(EVP_CIPHER_CTX* ctx,
                                const char* cipher_name,
                                const unsigned char* key,
                                size_t key_len)
{
    openssl_state_remember(ctx, cipher_name, key, key_len, nullptr, 0);
}

void openssl_state_remember_iv(EVP_CIPHER_CTX* ctx,
                               const char* cipher_name,
                               const unsigned char* iv,
                               size_t iv_len)
{
    openssl_state_remember(ctx, cipher_name, nullptr, 0, iv, iv_len);
}

bool openssl_state_lookup(const EVP_CIPHER_CTX* ctx, OpenSSLState& out)
{
    if (!ctx) return false;

    std::lock_guard<std::mutex> lock(state_mutex);
    auto it = ctx_state_map.find(ctx);
    if (it == ctx_state_map.end()) {
        return false;
    }

    out = it->second;
    return true;
}

void openssl_state_forget(const EVP_CIPHER_CTX* ctx)
{
    if (!ctx) return;

    std::lock_guard<std::mutex> lock(state_mutex);
    ctx_state_map.erase(ctx);
}