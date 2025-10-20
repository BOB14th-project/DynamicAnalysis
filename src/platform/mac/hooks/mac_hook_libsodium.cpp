// src/platform/mac/hooks/mac_hook_libsodium.cpp
#include "common/pch.h"
#include "common/output.h"
#include "common/reentry_guard.h"
#include "platform/mac/resolver.h"

#include <dlfcn.h>

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

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) \
    static const struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };
#endif

#define RESOLVE_SYM(var, name_literal)                                            \
    do {                                                                          \
        if (!(var)) {                                                             \
            (var) = reinterpret_cast<decltype(var)>(resolve_libsodium_symbol(name_literal)); \
        }                                                                         \
    } while (0)

template <typename T>
static inline int call_real(T fn) {
    return fn ? 0 : -1;
}

void* resolve_libsodium_symbol(const char* name) {
    if (!name || !*name) return nullptr;

    if (void* sym = resolve_next_symbol(name)) {
        return sym;
    }

    static const char* kLibNames[] = {
        "libsodium.dylib",
        "libsodium.23.dylib",
        "/opt/homebrew/lib/libsodium.dylib",
        "/usr/local/lib/libsodium.dylib",
        nullptr
    };

    for (const char* candidate : kLibNames) {
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

    const char* verbose = std::getenv("HOOK_VERBOSE");
    if (verbose && *verbose == '1') {
        std::fprintf(stderr, "[hook_macos] libsodium symbol '%s' unresolved\n", name);
    }
    return nullptr;
}

} // namespace

// crypto_aead_chacha20poly1305_ietf_encrypt
using fn_crypto_aead_chacha20poly1305_ietf_encrypt =
    int (*)(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*, const unsigned char*);
using fn_crypto_aead_chacha20poly1305_ietf_decrypt =
    int (*)(unsigned char*, unsigned long long*, unsigned char*, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*);
using fn_crypto_aead_chacha20poly1305_ietf_encrypt_detached =
    int (*)(unsigned char*, unsigned char*, unsigned long long*, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*, const unsigned char*);
using fn_crypto_aead_chacha20poly1305_ietf_decrypt_detached =
    int (*)(unsigned char*, unsigned char*, const unsigned char*, unsigned long long, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*);

static fn_crypto_aead_chacha20poly1305_ietf_encrypt real_crypto_aead_chacha20poly1305_ietf_encrypt = nullptr;
static fn_crypto_aead_chacha20poly1305_ietf_decrypt real_crypto_aead_chacha20poly1305_ietf_decrypt = nullptr;
static fn_crypto_aead_chacha20poly1305_ietf_encrypt_detached real_crypto_aead_chacha20poly1305_ietf_encrypt_detached = nullptr;
static fn_crypto_aead_chacha20poly1305_ietf_decrypt_detached real_crypto_aead_chacha20poly1305_ietf_decrypt_detached = nullptr;

extern "C" int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char* c,
                                                         unsigned long long* clen_p,
                                                         const unsigned char* m,
                                                         unsigned long long mlen,
                                                         const unsigned char* ad,
                                                         unsigned long long adlen,
                                                         const unsigned char* nsec,
                                                         const unsigned char* npub,
                                                         const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_chacha20poly1305_ietf_encrypt, "crypto_aead_chacha20poly1305_ietf_encrypt");
    if (!real_crypto_aead_chacha20poly1305_ietf_encrypt) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    }
    int ret = real_crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    if (ret == 0) {
        const unsigned char* tag_ptr = nullptr;
        if (c && clen_p && *clen_p >= kChacha20Poly1305Ietf.tag_len) {
            tag_ptr = c + (*clen_p - kChacha20Poly1305Ietf.tag_len);
        }
        log_event(kChacha20Poly1305Ietf,
                  "crypto_aead_chacha20poly1305_ietf_encrypt",
                  "enc",
                  k,
                  k ? kChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kChacha20Poly1305Ietf.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kChacha20Poly1305Ietf.tag_len : 0);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_chacha20poly1305_ietf_encrypt, crypto_aead_chacha20poly1305_ietf_encrypt)

extern "C" int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char* m,
                                                         unsigned long long* mlen_p,
                                                         unsigned char* nsec,
                                                         const unsigned char* c,
                                                         unsigned long long clen,
                                                         const unsigned char* ad,
                                                         unsigned long long adlen,
                                                         const unsigned char* npub,
                                                         const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_chacha20poly1305_ietf_decrypt, "crypto_aead_chacha20poly1305_ietf_decrypt");
    if (!real_crypto_aead_chacha20poly1305_ietf_decrypt) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
    }
    int ret = real_crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
    if (ret == 0) {
        const unsigned char* tag_ptr = (c && clen >= kChacha20Poly1305Ietf.tag_len)
            ? c + (clen - kChacha20Poly1305Ietf.tag_len)
            : nullptr;
        log_event(kChacha20Poly1305Ietf,
                  "crypto_aead_chacha20poly1305_ietf_decrypt",
                  "dec",
                  k,
                  k ? kChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kChacha20Poly1305Ietf.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kChacha20Poly1305Ietf.tag_len : 0);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_chacha20poly1305_ietf_decrypt, crypto_aead_chacha20poly1305_ietf_decrypt)

extern "C" int crypto_aead_chacha20poly1305_ietf_encrypt_detached(unsigned char* c,
                                                                  unsigned char* mac,
                                                                  unsigned long long* maclen_p,
                                                                  const unsigned char* m,
                                                                  unsigned long long mlen,
                                                                  const unsigned char* ad,
                                                                  unsigned long long adlen,
                                                                  const unsigned char* nsec,
                                                                  const unsigned char* npub,
                                                                  const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_chacha20poly1305_ietf_encrypt_detached,
                "crypto_aead_chacha20poly1305_ietf_encrypt_detached");
    if (!real_crypto_aead_chacha20poly1305_ietf_encrypt_detached) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
    }
    int ret = real_crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
    if (ret == 0) {
        size_t tag_len = 0;
        if (mac && maclen_p && *maclen_p > 0) {
            tag_len = static_cast<size_t>(*maclen_p);
        } else if (mac) {
            tag_len = kChacha20Poly1305Ietf.tag_len;
        }
        log_event(kChacha20Poly1305Ietf,
                  "crypto_aead_chacha20poly1305_ietf_encrypt_detached",
                  "enc",
                  k,
                  k ? kChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kChacha20Poly1305Ietf.nonce_len : 0,
                  mac,
                  tag_len);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_chacha20poly1305_ietf_encrypt_detached, crypto_aead_chacha20poly1305_ietf_encrypt_detached)

extern "C" int crypto_aead_chacha20poly1305_ietf_decrypt_detached(unsigned char* m,
                                                                  unsigned char* nsec,
                                                                  const unsigned char* c,
                                                                  unsigned long long clen,
                                                                  const unsigned char* mac,
                                                                  unsigned long long maclen,
                                                                  const unsigned char* ad,
                                                                  unsigned long long adlen,
                                                                  const unsigned char* npub,
                                                                  const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_chacha20poly1305_ietf_decrypt_detached,
                "crypto_aead_chacha20poly1305_ietf_decrypt_detached");
    if (!real_crypto_aead_chacha20poly1305_ietf_decrypt_detached) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, maclen, ad, adlen, npub, k);
    }
    int ret = real_crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, maclen, ad, adlen, npub, k);
    if (ret == 0) {
        log_event(kChacha20Poly1305Ietf,
                  "crypto_aead_chacha20poly1305_ietf_decrypt_detached",
                  "dec",
                  k,
                  k ? kChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kChacha20Poly1305Ietf.nonce_len : 0,
                  mac,
                  mac ? static_cast<size_t>(maclen) : 0);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_chacha20poly1305_ietf_decrypt_detached, crypto_aead_chacha20poly1305_ietf_decrypt_detached)

// xchacha20 variants
using fn_crypto_aead_xchacha20poly1305_ietf_encrypt =
    int (*)(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*, const unsigned char*);
using fn_crypto_aead_xchacha20poly1305_ietf_decrypt =
    int (*)(unsigned char*, unsigned long long*, unsigned char*, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*);
using fn_crypto_aead_xchacha20poly1305_ietf_encrypt_detached =
    int (*)(unsigned char*, unsigned char*, unsigned long long*, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*, const unsigned char*);
using fn_crypto_aead_xchacha20poly1305_ietf_decrypt_detached =
    int (*)(unsigned char*, unsigned char*, const unsigned char*, unsigned long long, const unsigned char*, unsigned long long,
            const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*);

static fn_crypto_aead_xchacha20poly1305_ietf_encrypt real_crypto_aead_xchacha20poly1305_ietf_encrypt = nullptr;
static fn_crypto_aead_xchacha20poly1305_ietf_decrypt real_crypto_aead_xchacha20poly1305_ietf_decrypt = nullptr;
static fn_crypto_aead_xchacha20poly1305_ietf_encrypt_detached real_crypto_aead_xchacha20poly1305_ietf_encrypt_detached = nullptr;
static fn_crypto_aead_xchacha20poly1305_ietf_decrypt_detached real_crypto_aead_xchacha20poly1305_ietf_decrypt_detached = nullptr;

extern "C" int crypto_aead_xchacha20poly1305_ietf_encrypt(unsigned char* c,
                                                          unsigned long long* clen_p,
                                                          const unsigned char* m,
                                                          unsigned long long mlen,
                                                          const unsigned char* ad,
                                                          unsigned long long adlen,
                                                          const unsigned char* nsec,
                                                          const unsigned char* npub,
                                                          const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_xchacha20poly1305_ietf_encrypt, "crypto_aead_xchacha20poly1305_ietf_encrypt");
    if (!real_crypto_aead_xchacha20poly1305_ietf_encrypt) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    }
    int ret = real_crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    if (ret == 0) {
        const unsigned char* tag_ptr = nullptr;
        if (c && clen_p && *clen_p >= kXChacha20Poly1305Ietf.tag_len) {
            tag_ptr = c + (*clen_p - kXChacha20Poly1305Ietf.tag_len);
        }
        log_event(kXChacha20Poly1305Ietf,
                  "crypto_aead_xchacha20poly1305_ietf_encrypt",
                  "enc",
                  k,
                  k ? kXChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kXChacha20Poly1305Ietf.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kXChacha20Poly1305Ietf.tag_len : 0);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_encrypt)

extern "C" int crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char* m,
                                                          unsigned long long* mlen_p,
                                                          unsigned char* nsec,
                                                          const unsigned char* c,
                                                          unsigned long long clen,
                                                          const unsigned char* ad,
                                                          unsigned long long adlen,
                                                          const unsigned char* npub,
                                                          const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_xchacha20poly1305_ietf_decrypt, "crypto_aead_xchacha20poly1305_ietf_decrypt");
    if (!real_crypto_aead_xchacha20poly1305_ietf_decrypt) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
    }
    int ret = real_crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
    if (ret == 0) {
        const unsigned char* tag_ptr = (c && clen >= kXChacha20Poly1305Ietf.tag_len)
            ? c + (clen - kXChacha20Poly1305Ietf.tag_len)
            : nullptr;
        log_event(kXChacha20Poly1305Ietf,
                  "crypto_aead_xchacha20poly1305_ietf_decrypt",
                  "dec",
                  k,
                  k ? kXChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kXChacha20Poly1305Ietf.nonce_len : 0,
                  tag_ptr,
                  tag_ptr ? kXChacha20Poly1305Ietf.tag_len : 0);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_decrypt)

extern "C" int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(unsigned char* c,
                                                                   unsigned char* mac,
                                                                   unsigned long long* maclen_p,
                                                                   const unsigned char* m,
                                                                   unsigned long long mlen,
                                                                   const unsigned char* ad,
                                                                   unsigned long long adlen,
                                                                   const unsigned char* nsec,
                                                                   const unsigned char* npub,
                                                                   const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
                "crypto_aead_xchacha20poly1305_ietf_encrypt_detached");
    if (!real_crypto_aead_xchacha20poly1305_ietf_encrypt_detached) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
    }
    int ret = real_crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
    if (ret == 0) {
        size_t tag_len = 0;
        if (mac && maclen_p && *maclen_p > 0) {
            tag_len = static_cast<size_t>(*maclen_p);
        } else if (mac) {
            tag_len = kXChacha20Poly1305Ietf.tag_len;
        }
        log_event(kXChacha20Poly1305Ietf,
                  "crypto_aead_xchacha20poly1305_ietf_encrypt_detached",
                  "enc",
                  k,
                  k ? kXChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kXChacha20Poly1305Ietf.nonce_len : 0,
                  mac,
                  tag_len);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_xchacha20poly1305_ietf_encrypt_detached, crypto_aead_xchacha20poly1305_ietf_encrypt_detached)

extern "C" int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(unsigned char* m,
                                                                   unsigned char* nsec,
                                                                   const unsigned char* c,
                                                                   unsigned long long clen,
                                                                   const unsigned char* mac,
                                                                   unsigned long long maclen,
                                                                   const unsigned char* ad,
                                                                   unsigned long long adlen,
                                                                   const unsigned char* npub,
                                                                   const unsigned char* k) {
    RESOLVE_SYM(real_crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
                "crypto_aead_xchacha20poly1305_ietf_decrypt_detached");
    if (!real_crypto_aead_xchacha20poly1305_ietf_decrypt_detached) return -1;
    ReentryGuard guard;
    if (!guard) {
        return real_crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, maclen, ad, adlen, npub, k);
    }
    int ret = real_crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, maclen, ad, adlen, npub, k);
    if (ret == 0) {
        log_event(kXChacha20Poly1305Ietf,
                  "crypto_aead_xchacha20poly1305_ietf_decrypt_detached",
                  "dec",
                  k,
                  k ? kXChacha20Poly1305Ietf.key_len : 0,
                  npub,
                  npub ? kXChacha20Poly1305Ietf.nonce_len : 0,
                  mac,
                  mac ? static_cast<size_t>(maclen) : 0);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_aead_xchacha20poly1305_ietf_decrypt_detached, crypto_aead_xchacha20poly1305_ietf_decrypt_detached)

// secretbox
using fn_crypto_secretbox_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long,
                                         const unsigned char*, const unsigned char*);
using fn_crypto_secretbox_open_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long,
                                              const unsigned char*, const unsigned char*);

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
DYLD_INTERPOSE(crypto_secretbox_easy, crypto_secretbox_easy)

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
DYLD_INTERPOSE(crypto_secretbox_open_easy, crypto_secretbox_open_easy)

// box
using fn_crypto_box_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long,
                                   const unsigned char*, const unsigned char*, const unsigned char*);
using fn_crypto_box_open_easy = int (*)(unsigned char*, const unsigned char*, unsigned long long,
                                        const unsigned char*, const unsigned char*, const unsigned char*);

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
DYLD_INTERPOSE(crypto_box_easy, crypto_box_easy)

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
DYLD_INTERPOSE(crypto_box_open_easy, crypto_box_open_easy)

// signatures
using fn_crypto_sign_ed25519_detached = int (*)(unsigned char*, unsigned long long*,
                                                const unsigned char*, unsigned long long,
                                                const unsigned char*);
static fn_crypto_sign_ed25519_detached real_crypto_sign_ed25519_detached = nullptr;

using fn_crypto_sign_detached = int (*)(unsigned char*, unsigned long long*,
                                        const unsigned char*, unsigned long long,
                                        const unsigned char*);
static fn_crypto_sign_detached real_crypto_sign_detached = nullptr;

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
    if (ret == 0) {
        size_t sig_len = (sig && siglen_p) ? static_cast<size_t>(*siglen_p) : 0;
        log_sign_event("crypto_sign_ed25519_detached",
                       sk,
                       sk ? kSignSecretKeyLen : 0,
                       sig,
                       sig_len);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_sign_ed25519_detached, crypto_sign_ed25519_detached)

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
    if (ret == 0) {
        size_t sig_len = (sig && siglen_p) ? static_cast<size_t>(*siglen_p) : 0;
        log_sign_event("crypto_sign_detached",
                       sk,
                       sk ? kSignSecretKeyLen : 0,
                       sig,
                       sig_len);
    }
    return ret;
}
DYLD_INTERPOSE(crypto_sign_detached, crypto_sign_detached)
