// src/Linux/hooks/hook_boringssl.cpp
// Intercepts BoringSSL AEAD APIs (EVP_AEAD_CTX_*) to capture key material.

#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#if !__has_include(<openssl/aead.h>) || !__has_include(<openssl/base.h>)
#error "hook_boringssl.cpp requires BoringSSL headers"
#endif

#include <openssl/aead.h>
#include <openssl/base.h>

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

#define RESOLVE_SYM(var, name_literal)                                               \
    do {                                                                             \
        if (!(var)) {                                                                \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(name_literal)); \
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

using fn_EVP_AEAD_name = const char* (*)(const EVP_AEAD*);
static fn_EVP_AEAD_name real_EVP_AEAD_name = nullptr;

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

    std::string name = "AEAD";
    RESOLVE_SYM(real_EVP_AEAD_name, "EVP_AEAD_name");
    if (real_EVP_AEAD_name) {
        if (const char* aead_name = real_EVP_AEAD_name(aead)) {
            name = aead_name;
        }
    }

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

int EVP_AEAD_CTX_init(EVP_AEAD_CTX* ctx,
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

using fn_EVP_AEAD_CTX_cleanup = void (*)(EVP_AEAD_CTX*);
static fn_EVP_AEAD_CTX_cleanup real_EVP_AEAD_CTX_cleanup = nullptr;

void EVP_AEAD_CTX_cleanup(EVP_AEAD_CTX* ctx) {
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

using fn_EVP_AEAD_CTX_seal = int (*)(const EVP_AEAD_CTX*, uint8_t*, size_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t);
static fn_EVP_AEAD_CTX_seal real_EVP_AEAD_CTX_seal = nullptr;

int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX* ctx,
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
        return real_EVP_AEAD_CTX_seal(ctx, out, out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len);
    }

    AeadState state;
    bool have_state = lookup_state(ctx, state);

    std::vector<uint8_t> tag_snapshot;
    int ret = real_EVP_AEAD_CTX_seal(ctx, out, out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len);
    if (ret && have_state) {
        size_t nonce_clamped = clamp_len(nonce_len);
        const uint8_t* nonce_ptr = nonce && nonce_clamped ? nonce : nullptr;

        size_t tag_len = state.tag_len;
        if ((!tag_len || tag_len > kMaxSnapshot) && out_len && out && *out_len > 0) {
            size_t max_tag = std::min(*out_len, kMaxSnapshot);
            tag_len = max_tag;
        }

        if (out && out_len && tag_len > 0 && *out_len >= tag_len) {
            const uint8_t* tag_ptr = out + (*out_len - tag_len);
            tag_snapshot = snapshot_buffer(tag_ptr, tag_len);
        }

        log_event("EVP_AEAD_CTX_seal",
                  "enc",
                  state,
                  nonce_ptr,
                  nonce_ptr ? nonce_clamped : 0,
                  tag_snapshot.empty() ? nullptr : tag_snapshot.data(),
                  tag_snapshot.size());
    }
    return ret;
}

using fn_EVP_AEAD_CTX_open = int (*)(const EVP_AEAD_CTX*, uint8_t*, size_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t,
                                     const uint8_t*, size_t);
static fn_EVP_AEAD_CTX_open real_EVP_AEAD_CTX_open = nullptr;

int EVP_AEAD_CTX_open(const EVP_AEAD_CTX* ctx,
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
        return real_EVP_AEAD_CTX_open(ctx, out, out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len);
    }

    AeadState state;
    bool have_state = lookup_state(ctx, state);

    std::vector<uint8_t> tag_snapshot;
    int ret = real_EVP_AEAD_CTX_open(ctx, out, out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len);
    if (ret && have_state) {
        size_t nonce_clamped = clamp_len(nonce_len);
        const uint8_t* nonce_ptr = nonce && nonce_clamped ? nonce : nullptr;

        size_t tag_len = state.tag_len;
        if ((!tag_len || tag_len > kMaxSnapshot) && in && in_len > 0) {
            tag_len = std::min(in_len, kMaxSnapshot);
        }

        if (in && tag_len > 0 && in_len >= tag_len) {
            const uint8_t* tag_ptr = in + (in_len - tag_len);
            tag_snapshot = snapshot_buffer(tag_ptr, tag_len);
        }

        log_event("EVP_AEAD_CTX_open",
                  "dec",
                  state,
                  nonce_ptr,
                  nonce_ptr ? nonce_clamped : 0,
                  tag_snapshot.empty() ? nullptr : tag_snapshot.data(),
                  tag_snapshot.size());
    }
    return ret;
}

} // extern "C"
