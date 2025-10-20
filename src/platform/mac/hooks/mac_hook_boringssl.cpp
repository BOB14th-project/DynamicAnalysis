// src/platform/mac/hooks/mac_hook_boringssl.cpp
// Intercepts BoringSSL EVP_AEAD APIs on macOS using DYLD interposing.

#include "common/pch.h"
#include "common/output.h"
#include "common/reentry_guard.h"
#include "platform/mac/resolver.h"

#if !__has_include(<openssl/aead.h>) || !__has_include(<openssl/base.h>)
#error "mac_hook_boringssl.cpp requires BoringSSL headers"
#endif

#include <openssl/aead.h>
#include <openssl/base.h>

#include <dlfcn.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr const char* SURFACE = "boringssl";
constexpr size_t kMaxSnapshot = 512;

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) \
    static const struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };
#endif

static void* resolve_boringssl_symbol(const char* name) {
    if (!name || !*name) return nullptr;
    if (void* sym = resolve_next_symbol(name)) {
        return sym;
    }

    static const char* kCandidates[] = {
        "libboringssl.dylib",
        "libcrypto.dylib",
        "/opt/homebrew/lib/libboringssl.dylib",
        "/opt/homebrew/lib/libcrypto.dylib",
        "/usr/local/lib/libboringssl.dylib",
        "/usr/local/lib/libcrypto.dylib",
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
        std::fprintf(stderr, "[hook_macos] boringssl symbol '%s' unresolved\n", name);
    }
    return nullptr;
}

#define RESOLVE_SYM(var, name_literal)                                               \
    do {                                                                             \
        if (!(var)) {                                                                \
            (var) = reinterpret_cast<decltype(var)>(resolve_boringssl_symbol(name_literal)); \
        }                                                                            \
    } while (0)

struct AeadState {
    std::vector<uint8_t> key;
    std::string name;
    size_t tag_len = 0;
};

std::mutex g_state_mu;
std::unordered_map<const EVP_AEAD_CTX*, AeadState> g_states;

std::vector<uint8_t> snapshot_buffer(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return {};
    }
    size_t copy_len = std::min(len, kMaxSnapshot);
    std::vector<uint8_t> out(copy_len);
    std::memcpy(out.data(), data, copy_len);
    return out;
}

size_t clamp_len(size_t len) {
    return std::min(len, kMaxSnapshot);
}

using fn_EVP_AEAD_max_overhead = size_t (*)(const EVP_AEAD*);
static fn_EVP_AEAD_max_overhead real_EVP_AEAD_max_overhead = nullptr;

const char* describe_aead(const EVP_AEAD* aead) {
    if (!aead) {
        return "AEAD";
    }
    if (aead == EVP_aead_aes_256_gcm()) return "AES-256-GCM";
    if (aead == EVP_aead_aes_128_gcm()) return "AES-128-GCM";
    if (aead == EVP_aead_chacha20_poly1305()) return "CHACHA20-POLY1305";
    if (aead == EVP_aead_xchacha20_poly1305()) return "XCHACHA20-POLY1305";
    return "AEAD";
}

void remember_state(const EVP_AEAD_CTX* ctx,
                    const EVP_AEAD* aead,
                    const uint8_t* key,
                    size_t key_len,
                    size_t tag_len) {
    if (!ctx || !aead || !key || key_len == 0) {
        return;
    }
    auto key_copy = snapshot_buffer(key, key_len);
    if (key_copy.empty()) {
        return;
    }

    size_t effective_tag_len = tag_len;
    if (effective_tag_len == 0) {
        RESOLVE_SYM(real_EVP_AEAD_max_overhead, "EVP_AEAD_max_overhead");
        if (real_EVP_AEAD_max_overhead) {
            effective_tag_len = real_EVP_AEAD_max_overhead(aead);
        }
    }

    std::string name = describe_aead(aead);

    std::lock_guard<std::mutex> lock(g_state_mu);
    auto& state = g_states[ctx];
    state.key = std::move(key_copy);
    state.name = std::move(name);
    state.tag_len = effective_tag_len;
}

bool lookup_state(const EVP_AEAD_CTX* ctx, AeadState& out) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    auto it = g_states.find(ctx);
    if (it == g_states.end()) {
        return false;
    }
    out = it->second;
    return true;
}

void forget_state(const EVP_AEAD_CTX* ctx) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    g_states.erase(ctx);
}

void log_event(const char* api,
               const char* direction,
               const AeadState& state,
               const uint8_t* nonce,
               size_t nonce_len,
               const uint8_t* tag,
               size_t tag_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        state.name.c_str(),
        state.key.empty() ? nullptr : state.key.data(),
        static_cast<int>(state.key.size()),
        nonce && nonce_len ? nonce : nullptr,
        static_cast<int>(nonce_len),
        tag && tag_len ? tag : nullptr,
        static_cast<int>(tag_len));
}

} // namespace

extern "C" {

typedef struct engine_st ENGINE;

using fn_EVP_AEAD_CTX_init = int (*)(EVP_AEAD_CTX*, const EVP_AEAD*, const uint8_t*, size_t, size_t, ENGINE*);
static fn_EVP_AEAD_CTX_init real_EVP_AEAD_CTX_init = nullptr;

int hook_EVP_AEAD_CTX_init(EVP_AEAD_CTX* ctx,
                           const EVP_AEAD* aead,
                           const uint8_t* key,
                           size_t key_len,
                           size_t tag_len,
                           ENGINE* engine) {
    RESOLVE_SYM(real_EVP_AEAD_CTX_init, "EVP_AEAD_CTX_init");
    if (!real_EVP_AEAD_CTX_init) {
        return 0;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_EVP_AEAD_CTX_init(ctx, aead, key, key_len, tag_len, engine);
    }

    int ret = real_EVP_AEAD_CTX_init(ctx, aead, key, key_len, tag_len, engine);
    if (ret) {
        remember_state(ctx, aead, key, key_len, tag_len);
        AeadState state;
        if (lookup_state(ctx, state)) {
            log_event("EVP_AEAD_CTX_init",
                      "set_key",
                      state,
                      nullptr,
                      0,
                      nullptr,
                      0);
        }
    }
    return ret;
}
DYLD_INTERPOSE(hook_EVP_AEAD_CTX_init, EVP_AEAD_CTX_init)

using fn_EVP_AEAD_CTX_cleanup = void (*)(EVP_AEAD_CTX*);
static fn_EVP_AEAD_CTX_cleanup real_EVP_AEAD_CTX_cleanup = nullptr;

void hook_EVP_AEAD_CTX_cleanup(EVP_AEAD_CTX* ctx) {
    RESOLVE_SYM(real_EVP_AEAD_CTX_cleanup, "EVP_AEAD_CTX_cleanup");
    if (!real_EVP_AEAD_CTX_cleanup) {
        return;
    }

    ReentryGuard guard;
    if (!guard) {
        real_EVP_AEAD_CTX_cleanup(ctx);
        return;
    }

    forget_state(ctx);
    real_EVP_AEAD_CTX_cleanup(ctx);
}
DYLD_INTERPOSE(hook_EVP_AEAD_CTX_cleanup, EVP_AEAD_CTX_cleanup)

using fn_EVP_AEAD_CTX_seal = int (*)(const EVP_AEAD_CTX*, uint8_t*, size_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t);
static fn_EVP_AEAD_CTX_seal real_EVP_AEAD_CTX_seal = nullptr;

int hook_EVP_AEAD_CTX_seal(const EVP_AEAD_CTX* ctx,
                           uint8_t* out,
                           size_t* out_len,
                           size_t max_out_len,
                           const uint8_t* nonce,
                           size_t nonce_len,
                           const uint8_t* in,
                           size_t in_len,
                           const uint8_t* ad,
                           size_t ad_len) {
    RESOLVE_SYM(real_EVP_AEAD_CTX_seal, "EVP_AEAD_CTX_seal");
    if (!real_EVP_AEAD_CTX_seal) {
        return 0;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_EVP_AEAD_CTX_seal(ctx, out, out_len, max_out_len,
                                      nonce, nonce_len, in, in_len, ad, ad_len);
    }

    int ret = real_EVP_AEAD_CTX_seal(ctx, out, out_len, max_out_len,
                                     nonce, nonce_len, in, in_len, ad, ad_len);
    if (ret == 0) {
        AeadState state;
        if (lookup_state(ctx, state)) {
            size_t tag_len = state.tag_len;
            size_t actual_tag_len = 0;
            if (out && out_len && *out_len > in_len) {
                actual_tag_len = *out_len - in_len;
                actual_tag_len = clamp_len(actual_tag_len);
            } else if (tag_len) {
                actual_tag_len = clamp_len(tag_len);
            }
            const uint8_t* tag_ptr = (out && out_len && actual_tag_len <= *out_len)
                                         ? out + (*out_len - actual_tag_len)
                                         : nullptr;
            log_event("EVP_AEAD_CTX_seal",
                      "enc",
                      state,
                      nonce,
                      clamp_len(nonce_len),
                      tag_ptr,
                      clamp_len(actual_tag_len));
        }
    }
    (void)max_out_len;
    (void)ad;
    (void)ad_len;
    (void)in;
    (void)in_len;
    return ret;
}
DYLD_INTERPOSE(hook_EVP_AEAD_CTX_seal, EVP_AEAD_CTX_seal)

using fn_EVP_AEAD_CTX_open = int (*)(const EVP_AEAD_CTX*, uint8_t*, size_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t);
static fn_EVP_AEAD_CTX_open real_EVP_AEAD_CTX_open = nullptr;

int hook_EVP_AEAD_CTX_open(const EVP_AEAD_CTX* ctx,
                           uint8_t* out,
                           size_t* out_len,
                           size_t max_out_len,
                           const uint8_t* nonce,
                           size_t nonce_len,
                           const uint8_t* in,
                           size_t in_len,
                           const uint8_t* ad,
                           size_t ad_len) {
    RESOLVE_SYM(real_EVP_AEAD_CTX_open, "EVP_AEAD_CTX_open");
    if (!real_EVP_AEAD_CTX_open) {
        return 0;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_EVP_AEAD_CTX_open(ctx, out, out_len, max_out_len,
                                      nonce, nonce_len, in, in_len, ad, ad_len);
    }

    int ret = real_EVP_AEAD_CTX_open(ctx, out, out_len, max_out_len,
                                     nonce, nonce_len, in, in_len, ad, ad_len);
    if (ret == 0) {
        AeadState state;
        if (lookup_state(ctx, state)) {
            size_t tag_len = state.tag_len;
            log_event("EVP_AEAD_CTX_open",
                      "dec",
                      state,
                      nonce,
                      clamp_len(nonce_len),
                      in ? in + (in_len - clamp_len(tag_len)) : nullptr,
                      clamp_len(tag_len));
        }
    }
    (void)max_out_len;
    (void)ad;
    (void)ad_len;
    (void)in;
    (void)in_len;
    return ret;
}
DYLD_INTERPOSE(hook_EVP_AEAD_CTX_open, EVP_AEAD_CTX_open)

} // extern "C"
