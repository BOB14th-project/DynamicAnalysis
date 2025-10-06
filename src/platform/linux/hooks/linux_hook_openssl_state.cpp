#include "common/hook_openssl_state.h"

#include <mutex>
#include <unordered_map>
#include <cstring>

namespace {

std::mutex g_mu;
std::unordered_map<const EVP_CIPHER_CTX*, OpenSSLState> g_states;

} // namespace

static void copy_buf(std::vector<unsigned char>& dst,
                     const unsigned char* src,
                     size_t len) {
    if (!src || len == 0) {
        return;
    }
    dst.assign(src, src + len);
}

void openssl_state_remember(EVP_CIPHER_CTX* ctx,
                            const char* cipher_name,
                            const unsigned char* key,
                            size_t key_len,
                            const unsigned char* iv,
                            size_t iv_len) {
    if (!ctx) return;
    std::lock_guard<std::mutex> lock(g_mu);
    auto& st = g_states[ctx];
    if (cipher_name && *cipher_name) {
        st.cipher_name = cipher_name;
    }
    if (key && key_len) {
        copy_buf(st.key, key, key_len);
    }
    if (iv && iv_len) {
        copy_buf(st.iv, iv, iv_len);
    }
}

void openssl_state_remember_key(EVP_CIPHER_CTX* ctx,
                                const char* cipher_name,
                                const unsigned char* key,
                                size_t key_len) {
    if (!ctx || !key || key_len == 0) return;
    std::lock_guard<std::mutex> lock(g_mu);
    auto& st = g_states[ctx];
    if (cipher_name && *cipher_name) {
        st.cipher_name = cipher_name;
    }
    copy_buf(st.key, key, key_len);
}

void openssl_state_remember_iv(EVP_CIPHER_CTX* ctx,
                               const char* cipher_name,
                               const unsigned char* iv,
                               size_t iv_len) {
    if (!ctx || !iv || iv_len == 0) return;
    std::lock_guard<std::mutex> lock(g_mu);
    auto& st = g_states[ctx];
    if (cipher_name && *cipher_name) {
        st.cipher_name = cipher_name;
    }
    copy_buf(st.iv, iv, iv_len);
}

bool openssl_state_lookup(const EVP_CIPHER_CTX* ctx, OpenSSLState& out) {
    if (!ctx) return false;
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_states.find(ctx);
    if (it == g_states.end()) {
        return false;
    }
    out = it->second;
    return true;
}

void openssl_state_forget(const EVP_CIPHER_CTX* ctx) {
    if (!ctx) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_states.erase(ctx);
}
