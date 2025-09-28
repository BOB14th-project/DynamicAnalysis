// src/Linux/hooks/hook_gnutls.cpp
// Capture symmetric key usage from selected GnuTLS cipher APIs.

#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#if !__has_include(<gnutls/crypto.h>) || !__has_include(<gnutls/gnutls.h>)
#error "hook_gnutls.cpp requires GnuTLS headers"
#endif

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

static constexpr const char* SURFACE = "gnutls";

#define RESOLVE_SYM(var, name_literal)                                               \
    do {                                                                             \
        if (!(var)) {                                                                \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(name_literal)); \
        }                                                                            \
    } while (0)

namespace {

constexpr size_t kMaxKeySnapshot = 512;
constexpr size_t kMaxIvSnapshot = 128;
constexpr size_t kMaxTagSnapshot = 128;

struct CipherState {
    std::string cipher_name;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
};

static std::mutex g_state_mu;
static std::unordered_map<gnutls_cipher_hd_t, CipherState> g_states;

static std::vector<unsigned char> copy_limited(const void* data, size_t len, size_t max_len) {
    if (!data || len == 0) {
        return {};
    }
    size_t copy_len = std::min(len, max_len);
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    return std::vector<unsigned char>(bytes, bytes + static_cast<std::ptrdiff_t>(copy_len));
}

static std::string cipher_name_from_alg(gnutls_cipher_algorithm_t alg) {
    const char* name = gnutls_cipher_get_name(alg);
    return name ? std::string(name) : std::string();
}

static void remember_state(gnutls_cipher_hd_t handle, const CipherState& state) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    g_states[handle] = state;
}

static std::optional<CipherState> fetch_state(gnutls_cipher_hd_t handle) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    auto it = g_states.find(handle);
    if (it == g_states.end()) {
        return std::nullopt;
    }
    return it->second;
}

static void forget_state(gnutls_cipher_hd_t handle) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    g_states.erase(handle);
}

static void update_state_iv(gnutls_cipher_hd_t handle, const unsigned char* iv, size_t iv_len) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    auto it = g_states.find(handle);
    if (it == g_states.end()) {
        return;
    }
    if (!iv || iv_len == 0) {
        it->second.iv.clear();
        return;
    }
    size_t copy_len = std::min(iv_len, kMaxIvSnapshot);
    it->second.iv.assign(iv, iv + static_cast<std::ptrdiff_t>(copy_len));
}

static void log_cipher_event(const char* api,
                             const char* direction,
                             const CipherState& state,
                             const unsigned char* tag,
                             size_t tag_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        state.cipher_name.empty() ? nullptr : state.cipher_name.c_str(),
        state.key.empty() ? nullptr : state.key.data(),
        static_cast<int>(state.key.size()),
        state.iv.empty() ? nullptr : state.iv.data(),
        static_cast<int>(state.iv.size()),
        (tag && tag_len) ? tag : nullptr,
        static_cast<int>(tag_len));
}

static CipherState make_state(gnutls_cipher_algorithm_t alg,
                              const gnutls_datum_t* key,
                              const gnutls_datum_t* iv) {
    CipherState state;
    state.cipher_name = cipher_name_from_alg(alg);
    if (key && key->data && key->size > 0) {
        state.key = copy_limited(key->data, key->size, kMaxKeySnapshot);
    }
    if (iv && iv->data && iv->size > 0) {
        state.iv = copy_limited(iv->data, iv->size, kMaxIvSnapshot);
    }
    return state;
}

} // namespace

extern "C" {

typedef int (*fn_gnutls_cipher_init)(gnutls_cipher_hd_t*, gnutls_cipher_algorithm_t,
                                     const gnutls_datum_t*, const gnutls_datum_t*);
static fn_gnutls_cipher_init real_gnutls_cipher_init = nullptr;

int gnutls_cipher_init(gnutls_cipher_hd_t* handle,
                       gnutls_cipher_algorithm_t cipher,
                       const gnutls_datum_t* key,
                       const gnutls_datum_t* iv) {
    RESOLVE_SYM(real_gnutls_cipher_init, "gnutls_cipher_init");
    if (!real_gnutls_cipher_init) {
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_gnutls_cipher_init(handle, cipher, key, iv);
    }

    int ret = real_gnutls_cipher_init(handle, cipher, key, iv);
    if (ret >= 0 && handle && *handle) {
        CipherState state = make_state(cipher, key, iv);
        remember_state(*handle, state);
        log_cipher_event("gnutls_cipher_init", "init", state, nullptr, 0);
    }
    return ret;
}

typedef void (*fn_gnutls_cipher_deinit)(gnutls_cipher_hd_t);
static fn_gnutls_cipher_deinit real_gnutls_cipher_deinit = nullptr;

void gnutls_cipher_deinit(gnutls_cipher_hd_t handle) {
    RESOLVE_SYM(real_gnutls_cipher_deinit, "gnutls_cipher_deinit");
    if (!real_gnutls_cipher_deinit) {
        return;
    }

    forget_state(handle);

    ReentryGuard guard;
    if (!guard) {
        real_gnutls_cipher_deinit(handle);
        return;
    }
    real_gnutls_cipher_deinit(handle);
}

typedef void (*fn_gnutls_cipher_set_iv)(gnutls_cipher_hd_t, void*, size_t);
static fn_gnutls_cipher_set_iv real_gnutls_cipher_set_iv = nullptr;

void gnutls_cipher_set_iv(gnutls_cipher_hd_t handle, void* iv, size_t ivlen) {
    RESOLVE_SYM(real_gnutls_cipher_set_iv, "gnutls_cipher_set_iv");
    if (!real_gnutls_cipher_set_iv) {
        return;
    }

    ReentryGuard guard;
    if (!guard) {
        real_gnutls_cipher_set_iv(handle, iv, ivlen);
        return;
    }

    real_gnutls_cipher_set_iv(handle, iv, ivlen);
    update_state_iv(handle, static_cast<const unsigned char*>(iv), ivlen);
    if (auto state = fetch_state(handle)) {
        log_cipher_event("gnutls_cipher_set_iv", "setiv", *state, nullptr, 0);
    }
}

typedef int (*fn_gnutls_cipher_encrypt)(gnutls_cipher_hd_t, void*, size_t);
static fn_gnutls_cipher_encrypt real_gnutls_cipher_encrypt = nullptr;

int gnutls_cipher_encrypt(gnutls_cipher_hd_t handle, void* text, size_t text_size) {
    RESOLVE_SYM(real_gnutls_cipher_encrypt, "gnutls_cipher_encrypt");
    if (!real_gnutls_cipher_encrypt) {
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_gnutls_cipher_encrypt(handle, text, text_size);
    }

    int ret = real_gnutls_cipher_encrypt(handle, text, text_size);
    if (ret >= 0) {
        if (auto state = fetch_state(handle)) {
            log_cipher_event("gnutls_cipher_encrypt", "enc", *state, nullptr, 0);
        }
    }
    (void)text;
    (void)text_size;
    return ret;
}

typedef int (*fn_gnutls_cipher_encrypt2)(gnutls_cipher_hd_t, const void*, size_t, void*, size_t);
static fn_gnutls_cipher_encrypt2 real_gnutls_cipher_encrypt2 = nullptr;

int gnutls_cipher_encrypt2(gnutls_cipher_hd_t handle,
                           const void* text, size_t text_size,
                           void* ciphertext, size_t ciphertext_size) {
    RESOLVE_SYM(real_gnutls_cipher_encrypt2, "gnutls_cipher_encrypt2");
    if (!real_gnutls_cipher_encrypt2) {
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_gnutls_cipher_encrypt2(handle, text, text_size, ciphertext, ciphertext_size);
    }

    int ret = real_gnutls_cipher_encrypt2(handle, text, text_size, ciphertext, ciphertext_size);
    if (ret >= 0) {
        if (auto state = fetch_state(handle)) {
            log_cipher_event("gnutls_cipher_encrypt2", "enc", *state, nullptr, 0);
        }
    }
    (void)text;
    (void)text_size;
    (void)ciphertext;
    (void)ciphertext_size;
    return ret;
}

typedef int (*fn_gnutls_cipher_decrypt)(gnutls_cipher_hd_t, void*, size_t);
static fn_gnutls_cipher_decrypt real_gnutls_cipher_decrypt = nullptr;

int gnutls_cipher_decrypt(gnutls_cipher_hd_t handle, void* cipher, size_t cipher_size) {
    RESOLVE_SYM(real_gnutls_cipher_decrypt, "gnutls_cipher_decrypt");
    if (!real_gnutls_cipher_decrypt) {
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_gnutls_cipher_decrypt(handle, cipher, cipher_size);
    }

    int ret = real_gnutls_cipher_decrypt(handle, cipher, cipher_size);
    if (ret >= 0) {
        if (auto state = fetch_state(handle)) {
            log_cipher_event("gnutls_cipher_decrypt", "dec", *state, nullptr, 0);
        }
    }
    (void)cipher;
    (void)cipher_size;
    return ret;
}

typedef int (*fn_gnutls_cipher_decrypt2)(gnutls_cipher_hd_t, const void*, size_t, void*, size_t);
static fn_gnutls_cipher_decrypt2 real_gnutls_cipher_decrypt2 = nullptr;

int gnutls_cipher_decrypt2(gnutls_cipher_hd_t handle,
                           const void* cipher, size_t cipher_size,
                           void* text, size_t text_size) {
    RESOLVE_SYM(real_gnutls_cipher_decrypt2, "gnutls_cipher_decrypt2");
    if (!real_gnutls_cipher_decrypt2) {
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_gnutls_cipher_decrypt2(handle, cipher, cipher_size, text, text_size);
    }

    int ret = real_gnutls_cipher_decrypt2(handle, cipher, cipher_size, text, text_size);
    if (ret >= 0) {
        if (auto state = fetch_state(handle)) {
            log_cipher_event("gnutls_cipher_decrypt2", "dec", *state, nullptr, 0);
        }
    }
    (void)cipher;
    (void)cipher_size;
    (void)text;
    (void)text_size;
    return ret;
}

typedef int (*fn_gnutls_cipher_add_auth)(gnutls_cipher_hd_t, const void*, size_t);
static fn_gnutls_cipher_add_auth real_gnutls_cipher_add_auth = nullptr;

int gnutls_cipher_add_auth(gnutls_cipher_hd_t handle, const void* data, size_t data_size) {
    RESOLVE_SYM(real_gnutls_cipher_add_auth, "gnutls_cipher_add_auth");
    if (!real_gnutls_cipher_add_auth) {
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_gnutls_cipher_add_auth(handle, data, data_size);
    }

    int ret = real_gnutls_cipher_add_auth(handle, data, data_size);
    if (ret >= 0) {
        if (auto state = fetch_state(handle)) {
            log_cipher_event("gnutls_cipher_add_auth", "aad", *state, nullptr, 0);
        }
    }
    (void)data;
    (void)data_size;
    return ret;
}

typedef int (*fn_gnutls_cipher_tag)(gnutls_cipher_hd_t, void*, size_t);
static fn_gnutls_cipher_tag real_gnutls_cipher_tag = nullptr;

int gnutls_cipher_tag(gnutls_cipher_hd_t handle, void* tag, size_t tag_size) {
    RESOLVE_SYM(real_gnutls_cipher_tag, "gnutls_cipher_tag");
    if (!real_gnutls_cipher_tag) {
        return GNUTLS_E_INTERNAL_ERROR;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_gnutls_cipher_tag(handle, tag, tag_size);
    }

    int ret = real_gnutls_cipher_tag(handle, tag, tag_size);
    if (ret >= 0 && tag && tag_size > 0) {
        auto tag_snapshot = copy_limited(tag, tag_size, kMaxTagSnapshot);
        if (auto state = fetch_state(handle)) {
            log_cipher_event("gnutls_cipher_tag", "tag", *state,
                             tag_snapshot.empty() ? nullptr : tag_snapshot.data(),
                             tag_snapshot.size());
        }
    }
    return ret;
}

} // extern "C"
