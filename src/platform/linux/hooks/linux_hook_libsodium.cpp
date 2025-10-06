// src/Linux/hooks/hook_libsodium.cpp
#include "common/pch.h"
#include "common/output.h"
#include "platform/linux/resolver.h"
#include "common/reentry_guard.h"

namespace {

constexpr const char* SURFACE = "libsodium";

struct AEADConfig {
    const char* cipher_name;
    size_t key_len;
    size_t nonce_len;
    size_t tag_len;
};

constexpr AEADConfig kChacha20Poly1305Ietf{ "chacha20poly1305-ietf", 32, 12, 16 };
constexpr AEADConfig kXChacha20Poly1305Ietf{ "xchacha20poly1305-ietf", 32, 24, 16 };
constexpr size_t kSignSecretKeyLen = 64; // ed25519 secret key length

void log_sign_event(const char* api,
                    const unsigned char* sk,
                    size_t sk_len,
                    const unsigned char* sig,
                    size_t sig_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        "sign",
        "sign-ed25519",
        sk_len ? sk : nullptr,
        static_cast<int>(sk_len),
        nullptr,
        0,
        sig_len ? sig : nullptr,
        static_cast<int>(sig_len));
}
constexpr AEADConfig kSecretboxEasy{ "secretbox-easy", 32, 24, 16 };
constexpr AEADConfig kBoxEasy{ "box-easy", 32, 24, 16 };

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

#define RESOLVE_SYM(var, name_literal)                                            \
    do {                                                                          \
        if (!(var)) {                                                             \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(name_literal)); \
        }                                                                         \
    } while (0)

void log_event(const AEADConfig& cfg,
               const char* api,
               const char* dir,
               const unsigned char* key,
               size_t key_len,
               const unsigned char* nonce,
               size_t nonce_len,
               const unsigned char* tag,
               size_t tag_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        dir,
        cfg.cipher_name,
        key_len ? key : nullptr,
        static_cast<int>(key_len),
        nonce_len ? nonce : nullptr,
        static_cast<int>(nonce_len),
        tag_len ? tag : nullptr,
        static_cast<int>(tag_len));
}

} // namespace

#define AEAD_ENC_PARAMS                                                            \
    unsigned char* c,                                                              \
    unsigned long long* clen_p,                                                    \
    const unsigned char* m,                                                        \
    unsigned long long mlen,                                                       \
    const unsigned char* ad,                                                       \
    unsigned long long adlen,                                                      \
    const unsigned char* nsec,                                                     \
    const unsigned char* npub,                                                     \
    const unsigned char* k

#define AEAD_DEC_PARAMS                                                            \
    unsigned char* m,                                                              \
    unsigned long long* mlen_p,                                                    \
    unsigned char* nsec,                                                           \
    const unsigned char* c,                                                        \
    unsigned long long clen,                                                       \
    const unsigned char* ad,                                                       \
    unsigned long long adlen,                                                      \
    const unsigned char* npub,                                                     \
    const unsigned char* k

#define AEAD_ENC_DETACHED_PARAMS                                                   \
    unsigned char* c,                                                              \
    unsigned char* mac,                                                            \
    unsigned long long* maclen_p,                                                  \
    const unsigned char* m,                                                        \
    unsigned long long mlen,                                                       \
    const unsigned char* ad,                                                       \
    unsigned long long adlen,                                                      \
    const unsigned char* nsec,                                                     \
    const unsigned char* npub,                                                     \
    const unsigned char* k

#define AEAD_DEC_DETACHED_PARAMS                                                   \
    unsigned char* m,                                                              \
    unsigned char* nsec,                                                           \
    const unsigned char* c,                                                        \
    unsigned long long clen,                                                       \
    const unsigned char* mac,                                                      \
    const unsigned char* ad,                                                       \
    unsigned long long adlen,                                                      \
    const unsigned char* npub,                                                     \
    const unsigned char* k

#define DEFINE_AEAD_ATTACHED_HOOK(PREFIX, CONFIG)                                  \
    using fn_##PREFIX##_encrypt = int (*)(AEAD_ENC_PARAMS);                         \
    using fn_##PREFIX##_decrypt = int (*)(AEAD_DEC_PARAMS);                         \
    static fn_##PREFIX##_encrypt real_##PREFIX##_encrypt = nullptr;                 \
    static fn_##PREFIX##_decrypt real_##PREFIX##_decrypt = nullptr;                 \
                                                                                    \
    extern "C" int PREFIX##_encrypt(AEAD_ENC_PARAMS) {                             \
        RESOLVE_SYM(real_##PREFIX##_encrypt, STRINGIFY(PREFIX##_encrypt));          \
        if (!real_##PREFIX##_encrypt) return -1;                                    \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return real_##PREFIX##_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k); \
        }                                                                           \
        int ret = real_##PREFIX##_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k); \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            const size_t tag_len = cfg.tag_len;                                     \
            const unsigned char* tag_ptr = (tag_len > 0 && c && clen_p && *clen_p >= tag_len) \
                ? c + (*clen_p - tag_len)                                          \
                : nullptr;                                                          \
            log_event(cfg, STRINGIFY(PREFIX##_encrypt), "enc",                     \
                      k, k ? cfg.key_len : 0,                                       \
                      npub, npub ? cfg.nonce_len : 0,                               \
                      tag_ptr, tag_ptr ? tag_len : 0);                              \
        }                                                                           \
        return ret;                                                                 \
    }                                                                               \
                                                                                    \
    extern "C" int PREFIX##_decrypt(AEAD_DEC_PARAMS) {                             \
        RESOLVE_SYM(real_##PREFIX##_decrypt, STRINGIFY(PREFIX##_decrypt));          \
        if (!real_##PREFIX##_decrypt) return -1;                                    \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return real_##PREFIX##_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k); \
        }                                                                           \
        int ret = real_##PREFIX##_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k); \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            const size_t tag_len = cfg.tag_len;                                     \
            const unsigned char* tag_ptr = (tag_len > 0 && c && clen >= tag_len)    \
                ? c + (clen - tag_len)                                              \
                : nullptr;                                                          \
            log_event(cfg, STRINGIFY(PREFIX##_decrypt), "dec",                     \
                      k, k ? cfg.key_len : 0,                                       \
                      npub, npub ? cfg.nonce_len : 0,                               \
                      tag_ptr, tag_ptr ? tag_len : 0);                              \
        }                                                                           \
        return ret;                                                                 \
    }

#define DEFINE_AEAD_DETACHED_HOOK(PREFIX, CONFIG)                                   \
    using fn_##PREFIX##_encrypt_detached = int (*)(AEAD_ENC_DETACHED_PARAMS);       \
    using fn_##PREFIX##_decrypt_detached = int (*)(AEAD_DEC_DETACHED_PARAMS);       \
    static fn_##PREFIX##_encrypt_detached real_##PREFIX##_encrypt_detached = nullptr; \
    static fn_##PREFIX##_decrypt_detached real_##PREFIX##_decrypt_detached = nullptr; \
                                                                                    \
    extern "C" int PREFIX##_encrypt_detached(AEAD_ENC_DETACHED_PARAMS) {           \
        RESOLVE_SYM(real_##PREFIX##_encrypt_detached,                               \
                    STRINGIFY(PREFIX##_encrypt_detached));                          \
        if (!real_##PREFIX##_encrypt_detached) return -1;                           \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return real_##PREFIX##_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k); \
        }                                                                           \
        int ret = real_##PREFIX##_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k); \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            size_t tag_len = 0;                                                     \
            if (mac && maclen_p && *maclen_p > 0) {                                 \
                tag_len = static_cast<size_t>(*maclen_p);                           \
            } else if (mac) {                                                       \
                tag_len = cfg.tag_len;                                              \
            }                                                                       \
            log_event(cfg, STRINGIFY(PREFIX##_encrypt_detached), "enc",            \
                      k, k ? cfg.key_len : 0,                                       \
                      npub, npub ? cfg.nonce_len : 0,                               \
                      mac, tag_len);                                                \
        }                                                                           \
        return ret;                                                                 \
    }                                                                               \
                                                                                    \
    extern "C" int PREFIX##_decrypt_detached(AEAD_DEC_DETACHED_PARAMS) {           \
        RESOLVE_SYM(real_##PREFIX##_decrypt_detached,                               \
                    STRINGIFY(PREFIX##_decrypt_detached));                          \
        if (!real_##PREFIX##_decrypt_detached) return -1;                           \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return real_##PREFIX##_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k); \
        }                                                                           \
        int ret = real_##PREFIX##_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k); \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            const size_t tag_len = mac ? cfg.tag_len : 0;                           \
            log_event(cfg, STRINGIFY(PREFIX##_decrypt_detached), "dec",            \
                      k, k ? cfg.key_len : 0,                                       \
                      npub, npub ? cfg.nonce_len : 0,                               \
                      mac, tag_len);                                                \
        }                                                                           \
        return ret;                                                                 \
    }

DEFINE_AEAD_ATTACHED_HOOK(crypto_aead_chacha20poly1305_ietf, kChacha20Poly1305Ietf)
DEFINE_AEAD_DETACHED_HOOK(crypto_aead_chacha20poly1305_ietf, kChacha20Poly1305Ietf)

DEFINE_AEAD_ATTACHED_HOOK(crypto_aead_xchacha20poly1305_ietf, kXChacha20Poly1305Ietf)
DEFINE_AEAD_DETACHED_HOOK(crypto_aead_xchacha20poly1305_ietf, kXChacha20Poly1305Ietf)

using fn_crypto_sign_detached = int (*)(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long, const unsigned char*);
static fn_crypto_sign_detached real_crypto_sign_detached = nullptr;

extern "C" int crypto_sign_detached(unsigned char* sig,
                                     unsigned long long* siglen_p,
                                     const unsigned char* m,
                                     unsigned long long mlen,
                                     const unsigned char* sk) {
    RESOLVE_SYM(real_crypto_sign_detached, "crypto_sign_detached");
    if (!real_crypto_sign_detached) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_sign_detached(sig, siglen_p, m, mlen, sk);
    }
    int ret = real_crypto_sign_detached(sig, siglen_p, m, mlen, sk);
    if (ret == 0 && sk) {
        unsigned long long siglen = siglen_p ? *siglen_p : 0ULL;
        log_sign_event("crypto_sign_detached",
                       sk,
                       kSignSecretKeyLen,
                       sig,
                       static_cast<size_t>(siglen));
    }
    return ret;
}

using fn_crypto_sign_ed25519_detached = int (*)(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long, const unsigned char*);
static fn_crypto_sign_ed25519_detached real_crypto_sign_ed25519_detached = nullptr;

extern "C" int crypto_sign_ed25519_detached(unsigned char* sig,
                                             unsigned long long* siglen_p,
                                             const unsigned char* m,
                                             unsigned long long mlen,
                                             const unsigned char* sk) {
    RESOLVE_SYM(real_crypto_sign_ed25519_detached, "crypto_sign_ed25519_detached");
    if (!real_crypto_sign_ed25519_detached) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk);
    }
    int ret = real_crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk);
    if (ret == 0 && sk) {
        unsigned long long siglen = siglen_p ? *siglen_p : 0ULL;
        log_sign_event("crypto_sign_ed25519_detached",
                       sk,
                       kSignSecretKeyLen,
                       sig,
                       static_cast<size_t>(siglen));
    }
    return ret;
}

using fn_crypto_secretbox_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*);
using fn_crypto_secretbox_open_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*);

static fn_crypto_secretbox_easy real_crypto_secretbox_easy = nullptr;
static fn_crypto_secretbox_open_easy real_crypto_secretbox_open_easy = nullptr;

extern "C" int crypto_secretbox_easy(unsigned char* c,
                                      const unsigned char* m,
                                      unsigned long long mlen,
                                      const unsigned char* n,
                                      const unsigned char* k) {
    RESOLVE_SYM(real_crypto_secretbox_easy, "crypto_secretbox_easy");
    if (!real_crypto_secretbox_easy) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_secretbox_easy(c, m, mlen, n, k);
    }
    int ret = real_crypto_secretbox_easy(c, m, mlen, n, k);
    if (ret == 0) {
        const unsigned char* tag_ptr = c;
        log_event(kSecretboxEasy,
                  "crypto_secretbox_easy",
                  "enc",
                  k,
                  k ? kSecretboxEasy.key_len : 0,
                  n,
                  n ? kSecretboxEasy.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kSecretboxEasy.tag_len : 0);
    }
    return ret;
}

extern "C" int crypto_secretbox_open_easy(unsigned char* m,
                                           const unsigned char* c,
                                           unsigned long long clen,
                                           const unsigned char* n,
                                           const unsigned char* k) {
    RESOLVE_SYM(real_crypto_secretbox_open_easy, "crypto_secretbox_open_easy");
    if (!real_crypto_secretbox_open_easy) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_secretbox_open_easy(m, c, clen, n, k);
    }
    int ret = real_crypto_secretbox_open_easy(m, c, clen, n, k);
    if (ret == 0) {
        const unsigned char* tag_ptr = (c && clen >= kSecretboxEasy.tag_len) ? c : nullptr;
        log_event(kSecretboxEasy,
                  "crypto_secretbox_open_easy",
                  "dec",
                  k,
                  k ? kSecretboxEasy.key_len : 0,
                  n,
                  n ? kSecretboxEasy.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kSecretboxEasy.tag_len : 0);
    }
    return ret;
}

using fn_crypto_box_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*, const unsigned char*);
using fn_crypto_box_open_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*, const unsigned char*);

static fn_crypto_box_easy real_crypto_box_easy = nullptr;
static fn_crypto_box_open_easy real_crypto_box_open_easy = nullptr;

extern "C" int crypto_box_easy(unsigned char* c,
                                const unsigned char* m,
                                unsigned long long mlen,
                                const unsigned char* n,
                                const unsigned char* pk,
                                const unsigned char* sk) {
    RESOLVE_SYM(real_crypto_box_easy, "crypto_box_easy");
    if (!real_crypto_box_easy) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_box_easy(c, m, mlen, n, pk, sk);
    }
    int ret = real_crypto_box_easy(c, m, mlen, n, pk, sk);
    if (ret == 0) {
        const unsigned char* tag_ptr = c;
        log_event(kBoxEasy,
                  "crypto_box_easy",
                  "enc",
                  sk,
                  sk ? kBoxEasy.key_len : 0,
                  n,
                  n ? kBoxEasy.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kBoxEasy.tag_len : 0);
    }
    return ret;
}

extern "C" int crypto_box_open_easy(unsigned char* m,
                                     const unsigned char* c,
                                     unsigned long long clen,
                                     const unsigned char* n,
                                     const unsigned char* pk,
                                     const unsigned char* sk) {
    RESOLVE_SYM(real_crypto_box_open_easy, "crypto_box_open_easy");
    if (!real_crypto_box_open_easy) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_box_open_easy(m, c, clen, n, pk, sk);
    }
    int ret = real_crypto_box_open_easy(m, c, clen, n, pk, sk);
    if (ret == 0) {
        const unsigned char* tag_ptr = (c && clen >= kBoxEasy.tag_len) ? c : nullptr;
        log_event(kBoxEasy,
                  "crypto_box_open_easy",
                  "dec",
                  sk,
                  sk ? kBoxEasy.key_len : 0,
                  n,
                  n ? kBoxEasy.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kBoxEasy.tag_len : 0);
    }
    return ret;
}
