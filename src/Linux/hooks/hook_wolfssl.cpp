// src/Linux/hooks/hook_wolfssl.cpp
// Intercepts wolfSSL primitives (AES-GCM, AES-CBC, HMAC) to capture key material.

#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#if !__has_include(<wolfssl/wolfcrypt/aes.h>) || !__has_include(<wolfssl/wolfcrypt/hmac.h>)
#error "hook_wolfssl.cpp requires wolfSSL headers"
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr const char* SURFACE = "wolfssl";
constexpr size_t kMaxSnapshot = 512;
constexpr size_t kDefaultBlockSize = AES_BLOCK_SIZE;

struct AesState {
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
};

struct HmacState {
    int hash_type = 0;
    std::string hash_name;
    std::vector<unsigned char> key;
};

std::mutex g_aes_mu;
std::unordered_map<const Aes*, AesState> g_aes_states;

std::mutex g_hmac_mu;
std::unordered_map<const Hmac*, HmacState> g_hmac_states;

std::vector<unsigned char> snapshot_buffer(const unsigned char* data, size_t len) {
    if (!data || len == 0) {
        return {};
    }
    size_t copy_len = std::min(len, kMaxSnapshot);
    std::vector<unsigned char> out(copy_len);
    std::memcpy(out.data(), data, copy_len);
    return out;
}

void remember_key(const Aes* ctx, const unsigned char* key, size_t key_len) {
    if (!ctx || !key || key_len == 0) {
        return;
    }
    auto copy = snapshot_buffer(key, key_len);
    if (copy.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_aes_mu);
    auto& state = g_aes_states[ctx];
    state.key = std::move(copy);
}

void remember_iv(const Aes* ctx, const unsigned char* iv, size_t iv_len) {
    if (!ctx || !iv || iv_len == 0) {
        return;
    }
    auto copy = snapshot_buffer(iv, iv_len);
    std::lock_guard<std::mutex> lock(g_aes_mu);
    auto& state = g_aes_states[ctx];
    state.iv = std::move(copy);
}

bool lookup_aes_state(const Aes* ctx, AesState& out) {
    std::lock_guard<std::mutex> lock(g_aes_mu);
    auto it = g_aes_states.find(ctx);
    if (it == g_aes_states.end()) {
        return false;
    }
    out = it->second;
    return true;
}

void forget_aes_state(const Aes* ctx) {
    std::lock_guard<std::mutex> lock(g_aes_mu);
    g_aes_states.erase(ctx);
}

const char* hash_name_from_type(int type) {
    switch (type) {
        case WC_SHA: return "HMAC-SHA1";
        case WC_SHA224: return "HMAC-SHA224";
        case WC_SHA256: return "HMAC-SHA256";
        case WC_SHA384: return "HMAC-SHA384";
        case WC_SHA512: return "HMAC-SHA512";
        case WC_MD5: return "HMAC-MD5";
#ifdef WC_SHA3
        case WC_SHA3_224: return "HMAC-SHA3-224";
        case WC_SHA3_256: return "HMAC-SHA3-256";
        case WC_SHA3_384: return "HMAC-SHA3-384";
        case WC_SHA3_512: return "HMAC-SHA3-512";
#endif
        default: return "HMAC";
    }
}

size_t hash_tag_len_from_type(int type) {
    switch (type) {
        case WC_SHA: return 20;
        case WC_SHA224: return 28;
        case WC_SHA256: return 32;
        case WC_SHA384: return 48;
        case WC_SHA512: return 64;
        case WC_MD5: return 16;
#ifdef WC_SHA3
        case WC_SHA3_224: return 28;
        case WC_SHA3_256: return 32;
        case WC_SHA3_384: return 48;
        case WC_SHA3_512: return 64;
#endif
        default: return 0;
    }
}

void remember_hmac_state(const Hmac* ctx,
                         int hash_type,
                         const unsigned char* key,
                         size_t key_len) {
    if (!ctx || !key || key_len == 0) {
        return;
    }
    auto copy = snapshot_buffer(key, key_len);
    if (copy.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    auto& state = g_hmac_states[ctx];
    state.hash_type = hash_type;
    state.hash_name = hash_name_from_type(hash_type);
    state.key = std::move(copy);
}

bool lookup_hmac_state(const Hmac* ctx, HmacState& out) {
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    auto it = g_hmac_states.find(ctx);
    if (it == g_hmac_states.end()) {
        return false;
    }
    out = it->second;
    return true;
}

void forget_hmac_state(const Hmac* ctx) {
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    g_hmac_states.erase(ctx);
}

void log_event(const char* api,
               const char* direction,
               const char* cipher_name,
               const std::vector<unsigned char>& key,
               const unsigned char* iv,
               size_t iv_len,
               const unsigned char* tag,
               size_t tag_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        cipher_name,
        key.empty() ? nullptr : key.data(),
        static_cast<int>(key.size()),
        iv && iv_len ? iv : nullptr,
        static_cast<int>(iv_len),
        tag && tag_len ? tag : nullptr,
        static_cast<int>(tag_len));
}

#define RESOLVE_SYM(var, name_literal)                                               \
    do {                                                                             \
        if (!(var)) {                                                                \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(name_literal)); \
        }                                                                            \
    } while (0)

} // namespace

extern "C" {

using fn_wc_AesGcmSetKey = int (*)(Aes*, const byte*, word32);
static fn_wc_AesGcmSetKey real_wc_AesGcmSetKey = nullptr;

int wc_AesGcmSetKey(Aes* aes,
                    const byte* key,
                    word32 len) {
    RESOLVE_SYM(real_wc_AesGcmSetKey, "wc_AesGcmSetKey");
    if (!real_wc_AesGcmSetKey) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesGcmSetKey(aes, key, len);
    }

    int ret = real_wc_AesGcmSetKey(aes, key, len);
    if (ret == 0) {
        remember_key(aes, reinterpret_cast<const unsigned char*>(key), len);
        auto snapshot = snapshot_buffer(reinterpret_cast<const unsigned char*>(key), len);
        log_event("wc_AesGcmSetKey", "set_key", "AES-GCM", snapshot, nullptr, 0, nullptr, 0);
    }
    return ret;
}

using fn_wc_AesGcmSetKey_ex = int (*)(Aes*, const byte*, word32, word32);
static fn_wc_AesGcmSetKey_ex real_wc_AesGcmSetKey_ex = nullptr;

int wc_AesGcmSetKey_ex(Aes* aes,
                       const byte* key,
                       word32 len,
                       word32 kup) {
    RESOLVE_SYM(real_wc_AesGcmSetKey_ex, "wc_AesGcmSetKey_ex");
    if (!real_wc_AesGcmSetKey_ex) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesGcmSetKey_ex(aes, key, len, kup);
    }

    int ret = real_wc_AesGcmSetKey_ex(aes, key, len, kup);
    if (ret == 0) {
        remember_key(aes, reinterpret_cast<const unsigned char*>(key), len);
        auto snapshot = snapshot_buffer(reinterpret_cast<const unsigned char*>(key), len);
        log_event("wc_AesGcmSetKey_ex", "set_key", "AES-GCM", snapshot, nullptr, 0, nullptr, 0);
    }
    return ret;
}

using fn_wc_AesGcmEncrypt = int (*)(Aes*, byte*, const byte*, word32,
                                    const byte*, word32, byte*, word32,
                                    const byte*, word32);
static fn_wc_AesGcmEncrypt real_wc_AesGcmEncrypt = nullptr;

int wc_AesGcmEncrypt(Aes* aes,
                     byte* out,
                     const byte* in,
                     word32 sz,
                     const byte* iv,
                     word32 ivSz,
                     byte* authTag,
                     word32 authTagSz,
                     const byte* authIn,
                     word32 authInSz) {
    RESOLVE_SYM(real_wc_AesGcmEncrypt, "wc_AesGcmEncrypt");
    if (!real_wc_AesGcmEncrypt) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesGcmEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);
    }

    AesState state;
    lookup_aes_state(aes, state);
    int ret = real_wc_AesGcmEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);
    if (ret == 0) {
        size_t iv_len = iv && ivSz > 0 ? std::min(static_cast<size_t>(ivSz), kMaxSnapshot) : 0;
        size_t tag_len = authTag && authTagSz > 0 ? std::min(static_cast<size_t>(authTagSz), kMaxSnapshot) : 0;
        log_event("wc_AesGcmEncrypt",
                  "enc",
                  "AES-GCM",
                  state.key,
                  reinterpret_cast<const unsigned char*>(iv),
                  iv_len,
                  reinterpret_cast<const unsigned char*>(authTag),
                  tag_len);
    }
    return ret;
}

using fn_wc_AesGcmDecrypt = int (*)(Aes*, byte*, const byte*, word32,
                                    const byte*, word32, const byte*, word32,
                                    const byte*, word32);
static fn_wc_AesGcmDecrypt real_wc_AesGcmDecrypt = nullptr;

int wc_AesGcmDecrypt(Aes* aes,
                     byte* out,
                     const byte* in,
                     word32 sz,
                     const byte* iv,
                     word32 ivSz,
                     const byte* authTag,
                     word32 authTagSz,
                     const byte* authIn,
                     word32 authInSz) {
    RESOLVE_SYM(real_wc_AesGcmDecrypt, "wc_AesGcmDecrypt");
    if (!real_wc_AesGcmDecrypt) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesGcmDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);
    }

    AesState state;
    lookup_aes_state(aes, state);
    int ret = real_wc_AesGcmDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);
    if (ret == 0) {
        size_t iv_len = iv && ivSz > 0 ? std::min(static_cast<size_t>(ivSz), kMaxSnapshot) : 0;
        size_t tag_len = authTag && authTagSz > 0 ? std::min(static_cast<size_t>(authTagSz), kMaxSnapshot) : 0;
        log_event("wc_AesGcmDecrypt",
                  "dec",
                  "AES-GCM",
                  state.key,
                  reinterpret_cast<const unsigned char*>(iv),
                  iv_len,
                  reinterpret_cast<const unsigned char*>(authTag),
                  tag_len);
    }
    return ret;
}

using fn_wc_AesSetKey = int (*)(Aes*, const byte*, word32, const byte*, int);
static fn_wc_AesSetKey real_wc_AesSetKey = nullptr;

int wc_AesSetKey(Aes* aes,
                 const byte* userKey,
                 word32 keyLen,
                 const byte* iv,
                 int dir) {
    RESOLVE_SYM(real_wc_AesSetKey, "wc_AesSetKey");
    if (!real_wc_AesSetKey) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesSetKey(aes, userKey, keyLen, iv, dir);
    }

    int ret = real_wc_AesSetKey(aes, userKey, keyLen, iv, dir);
    if (ret == 0) {
        remember_key(aes, reinterpret_cast<const unsigned char*>(userKey), keyLen);
        if (iv) {
            remember_iv(aes, reinterpret_cast<const unsigned char*>(iv), kDefaultBlockSize);
        }
        AesState state;
        lookup_aes_state(aes, state);
        log_event("wc_AesSetKey",
                  "set_key",
                  "AES",
                  state.key,
                  state.iv.empty() ? nullptr : state.iv.data(),
                  state.iv.size(),
                  nullptr,
                  0);
    }
    return ret;
}

using fn_wc_AesSetIV = int (*)(Aes*, const byte*);
static fn_wc_AesSetIV real_wc_AesSetIV = nullptr;

int wc_AesSetIV(Aes* aes, const byte* iv) {
    RESOLVE_SYM(real_wc_AesSetIV, "wc_AesSetIV");
    if (!real_wc_AesSetIV) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesSetIV(aes, iv);
    }

    int ret = real_wc_AesSetIV(aes, iv);
    if (ret == 0) {
        remember_iv(aes, reinterpret_cast<const unsigned char*>(iv), kDefaultBlockSize);
        AesState state;
        if (lookup_aes_state(aes, state)) {
            log_event("wc_AesSetIV",
                      "set_iv",
                      "AES",
                      state.key,
                      state.iv.empty() ? nullptr : state.iv.data(),
                      state.iv.size(),
                      nullptr,
                      0);
        }
    }
    return ret;
}

using fn_wc_AesCbcEncrypt = int (*)(Aes*, byte*, const byte*, word32);
static fn_wc_AesCbcEncrypt real_wc_AesCbcEncrypt = nullptr;

int wc_AesCbcEncrypt(Aes* aes,
                     byte* out,
                     const byte* in,
                     word32 sz) {
    RESOLVE_SYM(real_wc_AesCbcEncrypt, "wc_AesCbcEncrypt");
    if (!real_wc_AesCbcEncrypt) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesCbcEncrypt(aes, out, in, sz);
    }

    AesState state;
    lookup_aes_state(aes, state);
    int ret = real_wc_AesCbcEncrypt(aes, out, in, sz);
    if (ret == 0) {
        log_event("wc_AesCbcEncrypt",
                  "enc",
                  "AES-CBC",
                  state.key,
                  state.iv.empty() ? nullptr : state.iv.data(),
                  state.iv.size(),
                  nullptr,
                  0);
    }
    return ret;
}

using fn_wc_AesCbcDecrypt = int (*)(Aes*, byte*, const byte*, word32);
static fn_wc_AesCbcDecrypt real_wc_AesCbcDecrypt = nullptr;

int wc_AesCbcDecrypt(Aes* aes,
                     byte* out,
                     const byte* in,
                     word32 sz) {
    RESOLVE_SYM(real_wc_AesCbcDecrypt, "wc_AesCbcDecrypt");
    if (!real_wc_AesCbcDecrypt) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_AesCbcDecrypt(aes, out, in, sz);
    }

    AesState state;
    lookup_aes_state(aes, state);
    int ret = real_wc_AesCbcDecrypt(aes, out, in, sz);
    if (ret == 0) {
        log_event("wc_AesCbcDecrypt",
                  "dec",
                  "AES-CBC",
                  state.key,
                  state.iv.empty() ? nullptr : state.iv.data(),
                  state.iv.size(),
                  nullptr,
                  0);
    }
    return ret;
}

using fn_wc_AesFree = void (*)(Aes*);
static fn_wc_AesFree real_wc_AesFree = nullptr;

void wc_AesFree(Aes* aes) {
    RESOLVE_SYM(real_wc_AesFree, "wc_AesFree");
    if (!real_wc_AesFree) {
        return;
    }

    ReentryGuard guard;
    if (!guard) {
        real_wc_AesFree(aes);
        return;
    }

    forget_aes_state(aes);
    real_wc_AesFree(aes);
}

using fn_wc_HmacSetKey = int (*)(Hmac*, int, const byte*, word32);
static fn_wc_HmacSetKey real_wc_HmacSetKey = nullptr;

int wc_HmacSetKey(Hmac* hmac,
                  int type,
                  const byte* key,
                  word32 keySz) {
    RESOLVE_SYM(real_wc_HmacSetKey, "wc_HmacSetKey");
    if (!real_wc_HmacSetKey) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_HmacSetKey(hmac, type, key, keySz);
    }

    int ret = real_wc_HmacSetKey(hmac, type, key, keySz);
    if (ret == 0) {
        remember_hmac_state(hmac, type, reinterpret_cast<const unsigned char*>(key), keySz);
        HmacState state;
        if (lookup_hmac_state(hmac, state)) {
            log_event("wc_HmacSetKey",
                      "set_key",
                      state.hash_name.c_str(),
                      state.key,
                      nullptr,
                      0,
                      nullptr,
                      0);
        }
    }
    return ret;
}

using fn_wc_HmacFinal = int (*)(Hmac*, byte*);
static fn_wc_HmacFinal real_wc_HmacFinal = nullptr;

int wc_HmacFinal(Hmac* hmac, byte* hash) {
    RESOLVE_SYM(real_wc_HmacFinal, "wc_HmacFinal");
    if (!real_wc_HmacFinal) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_wc_HmacFinal(hmac, hash);
    }

    HmacState state;
    bool have_state = lookup_hmac_state(hmac, state);
    int ret = real_wc_HmacFinal(hmac, hash);
    if (ret == 0 && have_state) {
        size_t tag_len = hash_tag_len_from_type(state.hash_type);
        if (tag_len == 0 && hash) {
            tag_len = kMaxSnapshot;
        }
        if (hash && tag_len > 0) {
            tag_len = std::min(tag_len, kMaxSnapshot);
        } else {
            tag_len = 0;
        }
        log_event("wc_HmacFinal",
                  "final",
                  state.hash_name.c_str(),
                  state.key,
                  nullptr,
                  0,
                  reinterpret_cast<const unsigned char*>(hash),
                  tag_len);
    }
    return ret;
}

using fn_wc_HmacFree = void (*)(Hmac*);
static fn_wc_HmacFree real_wc_HmacFree = nullptr;

void wc_HmacFree(Hmac* hmac) {
    RESOLVE_SYM(real_wc_HmacFree, "wc_HmacFree");
    if (!real_wc_HmacFree) {
        return;
    }

    ReentryGuard guard;
    if (!guard) {
        real_wc_HmacFree(hmac);
        return;
    }

    forget_hmac_state(hmac);
    real_wc_HmacFree(hmac);
}

} // extern "C"

