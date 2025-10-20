// src/Linux/hooks/hook_mbedtls.cpp
// Intercept selected mbedTLS primitives to capture key material and signatures.

#include "common/pch.h"
#include "common/output.h"
#include "platform/mac/resolver.h"
#include "common/reentry_guard.h"

#if !__has_include(<mbedtls/gcm.h>) || !__has_include(<mbedtls/md.h>)
#error "hook_mbedtls.cpp requires mbedTLS headers"
#endif

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <mbedtls/gcm.h>
#include <mbedtls/md.h>

#include <dlfcn.h>
#include <cstdio>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

static constexpr const char* SURFACE = "mbedtls";

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) \
    static const struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };
#endif

static void* resolve_mbedtls_symbol(const char* name) {
    if (!name || !*name) return nullptr;
    if (void* sym = resolve_next_symbol(name)) {
        return sym;
    }
    static const char* kCandidates[] = {
        "libmbedcrypto.dylib",
        "libmbedtls.dylib",
        "/opt/homebrew/lib/libmbedcrypto.dylib",
        "/opt/homebrew/lib/libmbedtls.dylib",
        "/usr/local/lib/libmbedcrypto.dylib",
        "/usr/local/lib/libmbedtls.dylib",
        nullptr
    };
    for (const char* candidate : kCandidates) {
        if (!candidate) break;
        void* handle = dlopen(candidate, RTLD_NOLOAD | RTLD_LAZY);
        if (!handle) {
            handle = dlopen(candidate, RTLD_LAZY | RTLD_LOCAL);
        }
        if (!handle) continue;
        if (void* sym = dlsym(handle, name)) {
            return sym;
        }
    }
    if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
        std::fprintf(stderr, "[hook_macos] mbedtls symbol '%s' unresolved\n", name);
    }
    return nullptr;
}

#define RESOLVE_SYM(var, name)                                                     \
    do {                                                                           \
        if (!(var)) {                                                              \
            (var) = reinterpret_cast<decltype(var)>(resolve_mbedtls_symbol(name)); \
        }                                                                          \
    } while (0)

namespace {

constexpr size_t kMaxTagSnapshot = 128;

struct GcmState {
    std::string cipher_name;
    std::vector<unsigned char> key;
};

static std::mutex g_gcm_mu;
static std::unordered_map<const mbedtls_gcm_context*, GcmState> g_gcm_states;

static std::mutex g_hmac_mu;
struct HmacState {
    std::string hash_name;
    std::vector<unsigned char> key;
};
static std::unordered_map<const mbedtls_md_context_t*, HmacState> g_hmac_states;

static std::string describe_gcm_cipher(mbedtls_cipher_id_t cipher, unsigned int keybits) {
    std::string name;
    switch (cipher) {
        case MBEDTLS_CIPHER_ID_AES:
            name = "AES-GCM";
            break;
        case MBEDTLS_CIPHER_ID_CAMELLIA:
            name = "CAMELLIA-GCM";
            break;
        default:
            name = "GCM";
            break;
    }
    if (keybits > 0) {
        name += '-';
        name += std::to_string(keybits);
    }
    return name;
}

static const mbedtls_md_info_t* (*real_mbedtls_md_info_from_ctx)(const mbedtls_md_context_t*) = nullptr;
static const char* (*real_mbedtls_md_get_name)(const mbedtls_md_info_t*) = nullptr;
static unsigned char (*real_mbedtls_md_get_size)(const mbedtls_md_info_t*) = nullptr;

static std::vector<unsigned char> copy_buffer_limited(const unsigned char* data,
                                                       size_t len,
                                                       size_t max_len) {
    if (!data || len == 0) {
        return {};
    }
    size_t copy_len = std::min(len, max_len);
    std::vector<unsigned char> out(copy_len);
    std::memcpy(out.data(), data, copy_len);
    return out;
}

static void remember_gcm_state(const mbedtls_gcm_context* ctx,
                               const std::string& cipher_name,
                               const unsigned char* key,
                               size_t key_len) {
    if (!ctx || !key || key_len == 0) {
        return;
    }
    GcmState state;
    state.cipher_name = cipher_name;
    state.key.assign(key, key + key_len);
    std::lock_guard<std::mutex> lock(g_gcm_mu);
    g_gcm_states[ctx] = std::move(state);
}

static GcmState lookup_gcm_state(const mbedtls_gcm_context* ctx) {
    std::lock_guard<std::mutex> lock(g_gcm_mu);
    auto it = g_gcm_states.find(ctx);
    if (it != g_gcm_states.end()) {
        return it->second;
    }
    return {};
}

static void forget_gcm_state(const mbedtls_gcm_context* ctx) {
    std::lock_guard<std::mutex> lock(g_gcm_mu);
    g_gcm_states.erase(ctx);
}

static void remember_hmac_state(const mbedtls_md_context_t* ctx,
                                const unsigned char* key,
                                size_t key_len) {
    if (!ctx || !key || key_len == 0) {
        return;
    }
    RESOLVE_SYM(real_mbedtls_md_info_from_ctx, "mbedtls_md_info_from_ctx");
    RESOLVE_SYM(real_mbedtls_md_get_name, "mbedtls_md_get_name");
    const mbedtls_md_info_t* info = real_mbedtls_md_info_from_ctx ? real_mbedtls_md_info_from_ctx(ctx) : nullptr;
    const char* name = (info && real_mbedtls_md_get_name) ? real_mbedtls_md_get_name(info) : "HMAC";
    HmacState state;
    state.hash_name = name ? name : "HMAC";
    state.key.assign(key, key + key_len);
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    g_hmac_states[ctx] = std::move(state);
}

static std::optional<HmacState> lookup_hmac_state(const mbedtls_md_context_t* ctx) {
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    auto it = g_hmac_states.find(ctx);
    if (it != g_hmac_states.end()) {
        return it->second;
    }
    return std::nullopt;
}

static void forget_hmac_state(const mbedtls_md_context_t* ctx) {
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    g_hmac_states.erase(ctx);
}

static void log_gcm_event(const char* api,
                           const GcmState& state,
                           const char* direction,
                           const unsigned char* iv,
                           size_t iv_len,
                           const unsigned char* tag,
                           size_t tag_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        state.cipher_name.empty() ? nullptr : state.cipher_name.c_str(),
        state.key.empty() ? nullptr : state.key.data(),
        static_cast<int>(state.key.size()),
        iv && iv_len ? iv : nullptr,
        static_cast<int>(iv_len),
        tag && tag_len ? tag : nullptr,
        static_cast<int>(tag_len));
}

static void log_hmac_event(const char* api,
                            const HmacState& state,
                            const char* direction,
                            const unsigned char* payload,
                            size_t payload_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        state.hash_name.empty() ? nullptr : state.hash_name.c_str(),
        state.key.empty() ? nullptr : state.key.data(),
        static_cast<int>(state.key.size()),
        payload && payload_len ? payload : nullptr,
        static_cast<int>(payload_len),
        nullptr,
        0);
}

} // namespace

extern "C" {

typedef int (*fn_mbedtls_gcm_setkey)(mbedtls_gcm_context*, mbedtls_cipher_id_t,
                                     const unsigned char*, unsigned int);
static fn_mbedtls_gcm_setkey real_mbedtls_gcm_setkey = nullptr;

int mbedtls_gcm_setkey(mbedtls_gcm_context* ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char* key,
                       unsigned int keybits) {
    RESOLVE_SYM(real_mbedtls_gcm_setkey, "mbedtls_gcm_setkey");
    if (!real_mbedtls_gcm_setkey) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_gcm_setkey(ctx, cipher, key, keybits);
    }

    int ret = real_mbedtls_gcm_setkey(ctx, cipher, key, keybits);
    if (ret == 0 && ctx && key && keybits % 8 == 0) {
        const size_t key_len = static_cast<size_t>(keybits / 8);
        auto cipher_name = describe_gcm_cipher(cipher, keybits);
        remember_gcm_state(ctx, cipher_name, key, key_len);
        ndjson_log_key_event(
            SURFACE,
            "mbedtls_gcm_setkey",
            "setkey",
            cipher_name.empty() ? nullptr : cipher_name.c_str(),
            key,
            static_cast<int>(key_len),
            nullptr,
            0,
            nullptr,
            0);
    }
    return ret;
}
DYLD_INTERPOSE(mbedtls_gcm_setkey, mbedtls_gcm_setkey)

typedef void (*fn_mbedtls_gcm_free)(mbedtls_gcm_context*);
static fn_mbedtls_gcm_free real_mbedtls_gcm_free = nullptr;

void mbedtls_gcm_free(mbedtls_gcm_context* ctx) {
    RESOLVE_SYM(real_mbedtls_gcm_free, "mbedtls_gcm_free");
    if (!real_mbedtls_gcm_free) {
        return;
    }

    forget_gcm_state(ctx);

    ReentryGuard guard;
    if (!guard) {
        real_mbedtls_gcm_free(ctx);
        return;
    }
    real_mbedtls_gcm_free(ctx);
}
DYLD_INTERPOSE(mbedtls_gcm_free, mbedtls_gcm_free)

typedef int (*fn_mbedtls_gcm_crypt_and_tag)(mbedtls_gcm_context*, int, size_t,
                                            const unsigned char*, size_t,
                                            const unsigned char*, size_t,
                                            const unsigned char*, unsigned char*,
                                            size_t, unsigned char*);
static fn_mbedtls_gcm_crypt_and_tag real_mbedtls_gcm_crypt_and_tag = nullptr;

int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context* ctx,
                              int mode,
                              size_t length,
                              const unsigned char* iv,
                              size_t iv_len,
                              const unsigned char* add,
                              size_t add_len,
                              const unsigned char* input,
                              unsigned char* output,
                              size_t tag_len,
                              unsigned char* tag) {
    RESOLVE_SYM(real_mbedtls_gcm_crypt_and_tag, "mbedtls_gcm_crypt_and_tag");
    if (!real_mbedtls_gcm_crypt_and_tag) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_gcm_crypt_and_tag(ctx, mode, length, iv, iv_len,
                                              add, add_len, input, output,
                                              tag_len, tag);
    }

    int ret = real_mbedtls_gcm_crypt_and_tag(ctx, mode, length, iv, iv_len,
                                             add, add_len, input, output,
                                             tag_len, tag);
    if (ret == 0) {
        auto state = lookup_gcm_state(ctx);
        const char* dir = (mode == MBEDTLS_GCM_ENCRYPT) ? "enc" : "dec";
        const size_t capped_tag_len = std::min(tag_len, kMaxTagSnapshot);
        log_gcm_event("mbedtls_gcm_crypt_and_tag",
                      state,
                      dir,
                      iv,
                      iv_len,
                      tag,
                      capped_tag_len);
    }
    (void)length;
    (void)add;
    (void)add_len;
    (void)input;
    (void)output;
    return ret;
}
DYLD_INTERPOSE(mbedtls_gcm_crypt_and_tag, mbedtls_gcm_crypt_and_tag)

typedef int (*fn_mbedtls_gcm_auth_decrypt)(mbedtls_gcm_context*, size_t,
                                           const unsigned char*, size_t,
                                           const unsigned char*, size_t,
                                           const unsigned char*, size_t,
                                           const unsigned char*, unsigned char*);
static fn_mbedtls_gcm_auth_decrypt real_mbedtls_gcm_auth_decrypt = nullptr;

int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context* ctx,
                             size_t length,
                             const unsigned char* iv,
                             size_t iv_len,
                             const unsigned char* add,
                             size_t add_len,
                             const unsigned char* tag,
                             size_t tag_len,
                             const unsigned char* input,
                             unsigned char* output) {
    RESOLVE_SYM(real_mbedtls_gcm_auth_decrypt, "mbedtls_gcm_auth_decrypt");
    if (!real_mbedtls_gcm_auth_decrypt) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_gcm_auth_decrypt(ctx, length, iv, iv_len, add, add_len,
                                             tag, tag_len, input, output);
    }

    int ret = real_mbedtls_gcm_auth_decrypt(ctx, length, iv, iv_len, add, add_len,
                                            tag, tag_len, input, output);
    if (ret == 0) {
        auto state = lookup_gcm_state(ctx);
        const size_t capped_tag_len = std::min(tag_len, kMaxTagSnapshot);
        log_gcm_event("mbedtls_gcm_auth_decrypt",
                      state,
                      "dec",
                      iv,
                      iv_len,
                      tag,
                      capped_tag_len);
    }
    (void)length;
    (void)add;
    (void)add_len;
    (void)input;
    (void)output;
    return ret;
}
DYLD_INTERPOSE(mbedtls_gcm_auth_decrypt, mbedtls_gcm_auth_decrypt)

typedef int (*fn_mbedtls_md_hmac_starts)(mbedtls_md_context_t*, const unsigned char*, size_t);
static fn_mbedtls_md_hmac_starts real_mbedtls_md_hmac_starts = nullptr;

typedef int (*fn_mbedtls_md_hmac_finish)(mbedtls_md_context_t*, unsigned char*);
static fn_mbedtls_md_hmac_finish real_mbedtls_md_hmac_finish = nullptr;

typedef void (*fn_mbedtls_md_free)(mbedtls_md_context_t*);
static fn_mbedtls_md_free real_mbedtls_md_free = nullptr;

int mbedtls_md_hmac_starts(mbedtls_md_context_t* ctx,
                           const unsigned char* key,
                           size_t keylen) {
    RESOLVE_SYM(real_mbedtls_md_hmac_starts, "mbedtls_md_hmac_starts");
    if (!real_mbedtls_md_hmac_starts) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_md_hmac_starts(ctx, key, keylen);
    }

    int ret = real_mbedtls_md_hmac_starts(ctx, key, keylen);
    if (ret == 0 && ctx && key && keylen > 0) {
        remember_hmac_state(ctx, key, keylen);
        RESOLVE_SYM(real_mbedtls_md_info_from_ctx, "mbedtls_md_info_from_ctx");
        RESOLVE_SYM(real_mbedtls_md_get_name, "mbedtls_md_get_name");
        const mbedtls_md_info_t* info = real_mbedtls_md_info_from_ctx ? real_mbedtls_md_info_from_ctx(ctx) : nullptr;
        const char* name = (info && real_mbedtls_md_get_name) ? real_mbedtls_md_get_name(info) : "HMAC";
        HmacState snapshot{name ? name : "HMAC", std::vector<unsigned char>(key, key + keylen)};
        log_hmac_event("mbedtls_md_hmac_starts", snapshot, "init", nullptr, 0);
    }
    return ret;
}
DYLD_INTERPOSE(mbedtls_md_hmac_starts, mbedtls_md_hmac_starts)

int mbedtls_md_hmac_finish(mbedtls_md_context_t* ctx, unsigned char* output) {
    RESOLVE_SYM(real_mbedtls_md_hmac_finish, "mbedtls_md_hmac_finish");
    if (!real_mbedtls_md_hmac_finish) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_md_hmac_finish(ctx, output);
    }

    int ret = real_mbedtls_md_hmac_finish(ctx, output);
    if (ret == 0 && ctx && output) {
        auto maybe_state = lookup_hmac_state(ctx);
        if (maybe_state.has_value()) {
            RESOLVE_SYM(real_mbedtls_md_info_from_ctx, "mbedtls_md_info_from_ctx");
            RESOLVE_SYM(real_mbedtls_md_get_size, "mbedtls_md_get_size");
            const mbedtls_md_info_t* info = real_mbedtls_md_info_from_ctx ? real_mbedtls_md_info_from_ctx(ctx) : nullptr;
            size_t hash_len = (info && real_mbedtls_md_get_size)
                                  ? static_cast<size_t>(real_mbedtls_md_get_size(info))
                                  : static_cast<size_t>(maybe_state->key.size());
            auto tag_snapshot = copy_buffer_limited(output, hash_len, kMaxTagSnapshot);
            ndjson_log_key_event(
                SURFACE,
                "mbedtls_md_hmac_finish",
                "final",
                maybe_state->hash_name.c_str(),
                maybe_state->key.empty() ? nullptr : maybe_state->key.data(),
                static_cast<int>(maybe_state->key.size()),
                nullptr,
                0,
                tag_snapshot.empty() ? nullptr : tag_snapshot.data(),
                static_cast<int>(tag_snapshot.size()));
        }
    }
    return ret;
}
DYLD_INTERPOSE(mbedtls_md_hmac_finish, mbedtls_md_hmac_finish)

void mbedtls_md_free(mbedtls_md_context_t* ctx) {
    RESOLVE_SYM(real_mbedtls_md_free, "mbedtls_md_free");
    if (!real_mbedtls_md_free) {
        return;
    }

    forget_hmac_state(ctx);

    ReentryGuard guard;
    if (!guard) {
        real_mbedtls_md_free(ctx);
        return;
    }
    real_mbedtls_md_free(ctx);
}
DYLD_INTERPOSE(mbedtls_md_free, mbedtls_md_free)

} // extern "C"
