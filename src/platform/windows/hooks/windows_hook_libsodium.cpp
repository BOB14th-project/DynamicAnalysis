// windows_hook_libsodium.cpp - Detours-based libsodium hooks
#include "common/pch.h"
#include "common/output.h"
#include "common/reentry_guard.h"

#include <windows.h>
#include <detours.h>

#include <sodium.h>
#include <algorithm>

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

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
constexpr AEADConfig kSecretboxEasy{ "secretbox-easy", 32, 24, 16 };
constexpr AEADConfig kBoxEasy{ "box-easy", 32, 24, 16 };
constexpr size_t kSignSecretKeyLen = 64; // ed25519 secret key length

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

#define AEAD_ENC_ARGS c, clen_p, m, mlen, ad, adlen, nsec, npub, k
#define AEAD_DEC_ARGS m, mlen_p, nsec, c, clen, ad, adlen, npub, k

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

#define AEAD_ENC_DETACHED_ARGS c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k
#define AEAD_DEC_DETACHED_ARGS m, nsec, c, clen, mac, ad, adlen, npub, k

#define DEFINE_AEAD_ATTACHED_HOOK(PREFIX, CONFIG)                                   \
    using fn_##PREFIX##_encrypt = decltype(&PREFIX##_encrypt);                      \
    using fn_##PREFIX##_decrypt = decltype(&PREFIX##_decrypt);                      \
    static fn_##PREFIX##_encrypt Real_##PREFIX##_encrypt = PREFIX##_encrypt;        \
    static fn_##PREFIX##_decrypt Real_##PREFIX##_decrypt = PREFIX##_decrypt;        \
                                                                                    \
    static int __cdecl Hook_##PREFIX##_encrypt(AEAD_ENC_PARAMS) {                   \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return Real_##PREFIX##_encrypt(AEAD_ENC_ARGS);                          \
        }                                                                           \
        int ret = Real_##PREFIX##_encrypt(AEAD_ENC_ARGS);                           \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            const size_t tag_len = cfg.tag_len;                                     \
            const unsigned char* tag_ptr = (c && clen_p && *clen_p >= tag_len)      \
                ? c + (*clen_p - tag_len)                                          \
                : nullptr;                                                          \
            log_event(cfg, STRINGIFY(PREFIX##_encrypt), "enc",                      \
                      k, k ? cfg.key_len : 0,                                       \
                      npub, npub ? cfg.nonce_len : 0,                               \
                      tag_ptr, tag_ptr ? tag_len : 0);                              \
        }                                                                           \
        return ret;                                                                 \
    }                                                                               \
                                                                                    \
    static int __cdecl Hook_##PREFIX##_decrypt(AEAD_DEC_PARAMS) {                   \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return Real_##PREFIX##_decrypt(AEAD_DEC_ARGS);                          \
        }                                                                           \
        int ret = Real_##PREFIX##_decrypt(AEAD_DEC_ARGS);                           \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            const size_t tag_len = cfg.tag_len;                                     \
            const unsigned char* tag_ptr = (c && clen >= tag_len)                   \
                ? c + (clen - tag_len)                                              \
                : nullptr;                                                          \
            log_event(cfg, STRINGIFY(PREFIX##_decrypt), "dec",                      \
                      k, k ? cfg.key_len : 0,                                       \
                      npub, npub ? cfg.nonce_len : 0,                               \
                      tag_ptr, tag_ptr ? tag_len : 0);                              \
        }                                                                           \
        return ret;                                                                 \
    }

#define DEFINE_AEAD_DETACHED_HOOK(PREFIX, CONFIG)                                   \
    using fn_##PREFIX##_encrypt_detached = decltype(&PREFIX##_encrypt_detached);    \
    using fn_##PREFIX##_decrypt_detached = decltype(&PREFIX##_decrypt_detached);    \
    static fn_##PREFIX##_encrypt_detached Real_##PREFIX##_encrypt_detached =        \
        PREFIX##_encrypt_detached;                                                  \
    static fn_##PREFIX##_decrypt_detached Real_##PREFIX##_decrypt_detached =        \
        PREFIX##_decrypt_detached;                                                  \
                                                                                    \
    static int __cdecl Hook_##PREFIX##_encrypt_detached(AEAD_ENC_DETACHED_PARAMS) { \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return Real_##PREFIX##_encrypt_detached(AEAD_ENC_DETACHED_ARGS);        \
        }                                                                           \
        int ret = Real_##PREFIX##_encrypt_detached(AEAD_ENC_DETACHED_ARGS);         \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            size_t tag_len = 0;                                                     \
            if (mac && maclen_p && *maclen_p > 0) {                                 \
                tag_len = static_cast<size_t>(*maclen_p);                           \
            } else if (mac) {                                                       \
                tag_len = cfg.tag_len;                                              \
            }                                                                       \
            log_event(cfg, STRINGIFY(PREFIX##_encrypt_detached), "enc",             \
                      k, k ? cfg.key_len : 0,                                       \
                      npub, npub ? cfg.nonce_len : 0,                               \
                      mac, tag_len);                                                \
        }                                                                           \
        return ret;                                                                 \
    }                                                                               \
                                                                                    \
    static int __cdecl Hook_##PREFIX##_decrypt_detached(AEAD_DEC_DETACHED_PARAMS) { \
        ReentryGuard guard;                                                         \
        if (!guard) {                                                               \
            return Real_##PREFIX##_decrypt_detached(AEAD_DEC_DETACHED_ARGS);        \
        }                                                                           \
        int ret = Real_##PREFIX##_decrypt_detached(AEAD_DEC_DETACHED_ARGS);         \
        if (ret == 0) {                                                             \
            const AEADConfig& cfg = (CONFIG);                                       \
            const size_t tag_len = mac ? cfg.tag_len : 0;                           \
            log_event(cfg, STRINGIFY(PREFIX##_decrypt_detached), "dec",             \
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

using fn_crypto_sign_detached = decltype(&crypto_sign_detached);
static fn_crypto_sign_detached Real_crypto_sign_detached = crypto_sign_detached;

static int __cdecl Hook_crypto_sign_detached(unsigned char* sig,
                                             unsigned long long* siglen_p,
                                             const unsigned char* m,
                                             unsigned long long mlen,
                                             const unsigned char* sk) {
    ReentryGuard guard;
    if (!guard) {
        return Real_crypto_sign_detached(sig, siglen_p, m, mlen, sk);
    }
    int ret = Real_crypto_sign_detached(sig, siglen_p, m, mlen, sk);
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

using fn_crypto_sign_ed25519_detached = decltype(&crypto_sign_ed25519_detached);
static fn_crypto_sign_ed25519_detached Real_crypto_sign_ed25519_detached =
    crypto_sign_ed25519_detached;

static int __cdecl Hook_crypto_sign_ed25519_detached(unsigned char* sig,
                                                     unsigned long long* siglen_p,
                                                     const unsigned char* m,
                                                     unsigned long long mlen,
                                                     const unsigned char* sk) {
    ReentryGuard guard;
    if (!guard) {
        return Real_crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk);
    }
    int ret = Real_crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk);
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

using fn_crypto_secretbox_easy = decltype(&crypto_secretbox_easy);
using fn_crypto_secretbox_open_easy = decltype(&crypto_secretbox_open_easy);
static fn_crypto_secretbox_easy Real_crypto_secretbox_easy = crypto_secretbox_easy;
static fn_crypto_secretbox_open_easy Real_crypto_secretbox_open_easy =
    crypto_secretbox_open_easy;

static int __cdecl Hook_crypto_secretbox_easy(unsigned char* c,
                                              const unsigned char* m,
                                              unsigned long long mlen,
                                              const unsigned char* n,
                                              const unsigned char* k) {
    ReentryGuard guard;
    if (!guard) {
        return Real_crypto_secretbox_easy(c, m, mlen, n, k);
    }
    int ret = Real_crypto_secretbox_easy(c, m, mlen, n, k);
    if (ret == 0) {
        log_event(kSecretboxEasy,
                  "crypto_secretbox_easy",
                  "enc",
                  k,
                  k ? kSecretboxEasy.key_len : 0,
                  n,
                  n ? kSecretboxEasy.nonce_len : 0,
                  c,
                  c ? kSecretboxEasy.tag_len : 0);
    }
    return ret;
}

static int __cdecl Hook_crypto_secretbox_open_easy(unsigned char* m,
                                                   const unsigned char* c,
                                                   unsigned long long clen,
                                                   const unsigned char* n,
                                                   const unsigned char* k) {
    ReentryGuard guard;
    if (!guard) {
        return Real_crypto_secretbox_open_easy(m, c, clen, n, k);
    }
    int ret = Real_crypto_secretbox_open_easy(m, c, clen, n, k);
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

using fn_crypto_box_easy = decltype(&crypto_box_easy);
using fn_crypto_box_open_easy = decltype(&crypto_box_open_easy);
static fn_crypto_box_easy Real_crypto_box_easy = crypto_box_easy;
static fn_crypto_box_open_easy Real_crypto_box_open_easy = crypto_box_open_easy;

static int __cdecl Hook_crypto_box_easy(unsigned char* c,
                                        const unsigned char* m,
                                        unsigned long long mlen,
                                        const unsigned char* n,
                                        const unsigned char* pk,
                                        const unsigned char* sk) {
    ReentryGuard guard;
    if (!guard) {
        return Real_crypto_box_easy(c, m, mlen, n, pk, sk);
    }
    int ret = Real_crypto_box_easy(c, m, mlen, n, pk, sk);
    if (ret == 0) {
        log_event(kBoxEasy,
                  "crypto_box_easy",
                  "enc",
                  sk,
                  sk ? kBoxEasy.key_len : 0,
                  n,
                  n ? kBoxEasy.nonce_len : 0,
                  c,
                  c ? kBoxEasy.tag_len : 0);
    }
    return ret;
}

static int __cdecl Hook_crypto_box_open_easy(unsigned char* m,
                                             const unsigned char* c,
                                             unsigned long long clen,
                                             const unsigned char* n,
                                             const unsigned char* pk,
                                             const unsigned char* sk) {
    ReentryGuard guard;
    if (!guard) {
        return Real_crypto_box_open_easy(m, c, clen, n, pk, sk);
    }
    int ret = Real_crypto_box_open_easy(m, c, clen, n, pk, sk);
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

static BOOL AttachDetour(PVOID* target, PVOID detour) {
    return DetourAttach(target, detour) == NO_ERROR;
}

static BOOL DetachDetour(PVOID* target, PVOID detour) {
    return DetourDetach(target, detour) == NO_ERROR;
}

} // anonymous namespace

extern "C" {

BOOL InstallLibsodiumHooks() {
    BOOL success = TRUE;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    success &= AttachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_encrypt,
                            Hook_crypto_aead_chacha20poly1305_ietf_encrypt);
    success &= AttachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_decrypt,
                            Hook_crypto_aead_chacha20poly1305_ietf_decrypt);
    success &= AttachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_encrypt_detached,
                            Hook_crypto_aead_chacha20poly1305_ietf_encrypt_detached);
    success &= AttachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_decrypt_detached,
                            Hook_crypto_aead_chacha20poly1305_ietf_decrypt_detached);

    success &= AttachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_encrypt,
                            Hook_crypto_aead_xchacha20poly1305_ietf_encrypt);
    success &= AttachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_decrypt,
                            Hook_crypto_aead_xchacha20poly1305_ietf_decrypt);
    success &= AttachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
                            Hook_crypto_aead_xchacha20poly1305_ietf_encrypt_detached);
    success &= AttachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
                            Hook_crypto_aead_xchacha20poly1305_ietf_decrypt_detached);

    success &= AttachDetour(&(PVOID&)Real_crypto_sign_detached,
                            Hook_crypto_sign_detached);
    success &= AttachDetour(&(PVOID&)Real_crypto_sign_ed25519_detached,
                            Hook_crypto_sign_ed25519_detached);

    success &= AttachDetour(&(PVOID&)Real_crypto_secretbox_easy,
                            Hook_crypto_secretbox_easy);
    success &= AttachDetour(&(PVOID&)Real_crypto_secretbox_open_easy,
                            Hook_crypto_secretbox_open_easy);

    success &= AttachDetour(&(PVOID&)Real_crypto_box_easy,
                            Hook_crypto_box_easy);
    success &= AttachDetour(&(PVOID&)Real_crypto_box_open_easy,
                            Hook_crypto_box_open_easy);

    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        success = FALSE;
    }
    return success;
}

BOOL UninstallLibsodiumHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_encrypt,
                 Hook_crypto_aead_chacha20poly1305_ietf_encrypt);
    DetachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_decrypt,
                 Hook_crypto_aead_chacha20poly1305_ietf_decrypt);
    DetachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_encrypt_detached,
                 Hook_crypto_aead_chacha20poly1305_ietf_encrypt_detached);
    DetachDetour(&(PVOID&)Real_crypto_aead_chacha20poly1305_ietf_decrypt_detached,
                 Hook_crypto_aead_chacha20poly1305_ietf_decrypt_detached);

    DetachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_encrypt,
                 Hook_crypto_aead_xchacha20poly1305_ietf_encrypt);
    DetachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_decrypt,
                 Hook_crypto_aead_xchacha20poly1305_ietf_decrypt);
    DetachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
                 Hook_crypto_aead_xchacha20poly1305_ietf_encrypt_detached);
    DetachDetour(&(PVOID&)Real_crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
                 Hook_crypto_aead_xchacha20poly1305_ietf_decrypt_detached);

    DetachDetour(&(PVOID&)Real_crypto_sign_detached,
                 Hook_crypto_sign_detached);
    DetachDetour(&(PVOID&)Real_crypto_sign_ed25519_detached,
                 Hook_crypto_sign_ed25519_detached);

    DetachDetour(&(PVOID&)Real_crypto_secretbox_easy,
                 Hook_crypto_secretbox_easy);
    DetachDetour(&(PVOID&)Real_crypto_secretbox_open_easy,
                 Hook_crypto_secretbox_open_easy);

    DetachDetour(&(PVOID&)Real_crypto_box_easy,
                 Hook_crypto_box_easy);
    DetachDetour(&(PVOID&)Real_crypto_box_open_easy,
                 Hook_crypto_box_open_easy);

    DetourTransactionCommit();
    return TRUE;
}

} // extern "C"
