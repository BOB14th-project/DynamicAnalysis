// src/Linux/hooks/hook_cryptodev.cpp
// Intercept /dev/crypto session creation to capture symmetric keys set via cryptodev.

#include "common/pch.h"
#include "common/output.h"
#include "platform/linux/resolver.h"
#include "common/reentry_guard.h"

#include <sys/ioctl.h>

#if __has_include(<crypto/cryptodev.h>)
#include <crypto/cryptodev.h>
#else
// Manual definitions for systems without crypto/cryptodev.h
#define CIOCGSESSION    _IOWR('c', 101, struct session_op)
#define CIOCKEY         _IOWR('c', 104, struct crypt_kop)
#define CIOCFSESSION    _IOW('c', 102, uint32_t)
#define CRK_MAXPARAM    8
#define CRK_MOD_EXP     0
#define CRK_MOD_EXP_CRT 1
#define CRK_DSA_SIGN    2
#define CRK_DSA_VERIFY  3
#define CRK_DH_COMPUTE_KEY 4

typedef char * caddr_t;

struct session_op {
    uint32_t cipher;
    uint32_t mac;
    uint32_t keylen;
    const uint8_t* key;
    uint32_t mackeylen;
    const uint8_t* mackey;
    uint32_t ses;
};

struct crparam {
    caddr_t crp_p;
    unsigned int crp_nbits;
};

struct crypt_kop {
    unsigned int crk_op;
    unsigned int crk_status;
    unsigned short crk_iparams;
    unsigned short crk_oparams;
    struct crparam crk_param[CRK_MAXPARAM];
};

// Common cipher constants
#define CRYPTO_DES_CBC      1
#define CRYPTO_3DES_CBC     2
#define CRYPTO_AES_CBC      11
#define CRYPTO_AES_ECB      12
#define CRYPTO_AES_CTR      13
#define CRYPTO_AES_GCM      14
#define CRYPTO_AES_CFB      15
#define CRYPTO_AES_OFB      16
#define CRYPTO_BLF_CBC      3
#define CRYPTO_CAST_CBC     4
#define CRYPTO_ARC4         5
#define CRYPTO_CHACHA20     17

#endif

#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <algorithm>

static constexpr const char* SURFACE = "cryptodev";

#define RESOLVE_SYM(var, name)                                                     \
    do {                                                                           \
        if (!(var)) {                                                              \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(name));    \
        }                                                                          \
    } while (0)

using ioctl_fn = int (*)(int, unsigned long, ...);
static ioctl_fn real_ioctl = nullptr;

struct SessionInfo {
    std::string cipher_name;
    std::vector<unsigned char> key;
};

static std::mutex g_session_mu;
static std::unordered_map<uint32_t, SessionInfo> g_sessions;

static const char* cipher_to_string(uint32_t cipher) {
    switch (cipher) {
        case CRYPTO_DES_CBC: return "DES-CBC";
        case CRYPTO_3DES_CBC: return "3DES-CBC";
#ifdef CRYPTO_AES_ECB
        case CRYPTO_AES_ECB: return "AES-ECB";
#endif
        case CRYPTO_AES_CBC: return "AES-CBC";
#ifdef CRYPTO_AES_CTR
        case CRYPTO_AES_CTR: return "AES-CTR";
#endif
#ifdef CRYPTO_AES_GCM
        case CRYPTO_AES_GCM: return "AES-GCM";
#endif
#ifdef CRYPTO_AES_CFB
        case CRYPTO_AES_CFB: return "AES-CFB";
#endif
#ifdef CRYPTO_AES_OFB
        case CRYPTO_AES_OFB: return "AES-OFB";
#endif
#ifdef CRYPTO_BLF_CBC
        case CRYPTO_BLF_CBC: return "BLOWFISH-CBC";
#endif
#ifdef CRYPTO_CAST_CBC
        case CRYPTO_CAST_CBC: return "CAST-CBC";
#endif
#ifdef CRYPTO_ARC4
        case CRYPTO_ARC4: return "ARC4";
#endif
#ifdef CRYPTO_CHACHA20
        case CRYPTO_CHACHA20: return "CHACHA20";
#endif
        default: return nullptr;
    }
}

static void remember_session(uint32_t ses, SessionInfo info) {
    std::lock_guard<std::mutex> lock(g_session_mu);
    g_sessions[ses] = std::move(info);
}

static void forget_session(uint32_t ses) {
    std::lock_guard<std::mutex> lock(g_session_mu);
    g_sessions.erase(ses);
}

// Extended CRK constants (may not be available in all systems)
#ifndef CRK_RSA_SIGN
#define CRK_RSA_SIGN 5
#endif
#ifndef CRK_RSA_VERIFY
#define CRK_RSA_VERIFY 6
#endif
#ifndef CRK_ECDSA_SIGN
#define CRK_ECDSA_SIGN 7
#endif
#ifndef CRK_ECDSA_VERIFY
#define CRK_ECDSA_VERIFY 8
#endif

static const char* kop_op_to_string(unsigned int op) {
    switch (op) {
        case CRK_MOD_EXP: return "CRK_MOD_EXP";
        case CRK_MOD_EXP_CRT: return "CRK_MOD_EXP_CRT";
        case CRK_DSA_SIGN: return "CRK_DSA_SIGN";
        case CRK_DSA_VERIFY: return "CRK_DSA_VERIFY";
        case CRK_DH_COMPUTE_KEY: return "CRK_DH_COMPUTE_KEY";
        case CRK_RSA_SIGN: return "CRK_RSA_SIGN";
        case CRK_RSA_VERIFY: return "CRK_RSA_VERIFY";
        case CRK_ECDSA_SIGN: return "CRK_ECDSA_SIGN";
        case CRK_ECDSA_VERIFY: return "CRK_ECDSA_VERIFY";
        default: return "CRK_UNKNOWN";
    }
}

static std::vector<unsigned char> copy_param(const struct crparam& p) {
    if (!p.crp_p || p.crp_nbits == 0) return {};
    // Convert bits to bytes (round up)
    size_t len_bytes = (p.crp_nbits + 7) / 8;
    size_t len = std::min<size_t>(len_bytes, 1024);
    std::vector<unsigned char> out(len);
    memcpy(out.data(), p.crp_p, len);
    return out;
}

extern "C" int ioctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void* arg = va_arg(args, void*);
    va_end(args);
    RESOLVE_SYM(real_ioctl, "ioctl");
    if (!real_ioctl)
        return -1;


    // Keep an immutable snapshot of incoming arguments before the kernel mutates them.
    session_op sess_before{};
    bool have_session_before = false;
    std::vector<unsigned char> key_copy;
    std::string cipher_name;

    struct crypt_kop kop_before{};
    std::vector<std::vector<unsigned char>> kop_params;

    if (request == CIOCGSESSION && arg) {
        std::memcpy(&sess_before, arg, sizeof(sess_before));
        have_session_before = true;

        if (sess_before.key && sess_before.keylen > 0 && sess_before.keylen < 4096) {
            key_copy.resize(static_cast<size_t>(sess_before.keylen));
            std::memcpy(key_copy.data(), sess_before.key, key_copy.size());
        }
        if (const char* cname = cipher_to_string(sess_before.cipher)) {
            cipher_name.assign(cname);
        }
    } else if (request == CIOCKEY && arg) {
        std::memcpy(&kop_before, arg, sizeof(kop_before));
        for (unsigned int i = 0; i < kop_before.crk_iparams && i < CRK_MAXPARAM; ++i) {
            kop_params.push_back(copy_param(kop_before.crk_param[i]));
        }
    }

    ReentryGuard guard;
    if (!guard)
        return real_ioctl(fd, request, arg);

    int ret = real_ioctl(fd, request, arg);

    if (request == CIOCGSESSION && arg && have_session_before) {
        session_op sess_after{};
        std::memcpy(&sess_after, arg, sizeof(sess_after));

        SessionInfo info;
        info.cipher_name = cipher_name;
        info.key = std::move(key_copy);

        remember_session(sess_after.ses, info);

        ndjson_log_key_event(
            SURFACE,
            "CIOCGSESSION",
            "init",
            info.cipher_name.empty() ? nullptr : info.cipher_name.c_str(),
            info.key.empty() ? nullptr : info.key.data(),
            static_cast<int>(info.key.size()),
            nullptr,
            0,
            nullptr,
            0);
    } else if (request == CIOCKEY && arg && !kop_params.empty()) {
        const char* op_name = kop_op_to_string(kop_before.crk_op);

        // Log detailed parameters based on operation type
        if (kop_before.crk_op == CRK_RSA_SIGN || kop_before.crk_op == CRK_RSA_VERIFY) {
            // RSA operations: typically have message digest and RSA parameters
            const unsigned char* digest_ptr = kop_params.size() > 0 && !kop_params[0].empty() ? kop_params[0].data() : nullptr;
            int digest_len = kop_params.size() > 0 ? static_cast<int>(kop_params[0].size()) : 0;

            const unsigned char* modulus_ptr = kop_params.size() > 1 && !kop_params[1].empty() ? kop_params[1].data() : nullptr;
            int modulus_len = kop_params.size() > 1 ? static_cast<int>(kop_params[1].size()) : 0;

            // Log with digest as IV and modulus as key for RSA operations
            ndjson_log_key_event(
                SURFACE,
                "CIOCKEY",
                op_name,
                "RSA",
                modulus_ptr,  // RSA modulus as key
                modulus_len,
                digest_ptr,   // Message digest as IV
                digest_len,
                nullptr,      // Signature would be in output params
                0);

            // Log additional parameters if available
            for (size_t i = 2; i < kop_params.size() && i < kop_before.crk_iparams; ++i) {
                if (!kop_params[i].empty()) {
                    char param_name[32];
                    snprintf(param_name, sizeof(param_name), "RSA-param-%zu", i);
                    ndjson_log_key_event(
                        SURFACE,
                        "CIOCKEY",
                        param_name,
                        "RSA",
                        kop_params[i].data(),
                        static_cast<int>(kop_params[i].size()),
                        nullptr, 0, nullptr, 0);
                }
            }
        } else if (kop_before.crk_op == CRK_DSA_SIGN || kop_before.crk_op == CRK_DSA_VERIFY) {
            // DSA operations: digest, p, q, g, private/public key
            const unsigned char* digest_ptr = kop_params.size() > 0 && !kop_params[0].empty() ? kop_params[0].data() : nullptr;
            int digest_len = kop_params.size() > 0 ? static_cast<int>(kop_params[0].size()) : 0;

            const unsigned char* p_ptr = kop_params.size() > 1 && !kop_params[1].empty() ? kop_params[1].data() : nullptr;
            int p_len = kop_params.size() > 1 ? static_cast<int>(kop_params[1].size()) : 0;

            ndjson_log_key_event(
                SURFACE,
                "CIOCKEY",
                op_name,
                "DSA",
                p_ptr,        // DSA p parameter as key
                p_len,
                digest_ptr,   // Message digest as IV
                digest_len,
                nullptr, 0);

            // Log q, g, and key parameters
            if (kop_params.size() > 2 && !kop_params[2].empty()) {
                ndjson_log_key_event(SURFACE, "CIOCKEY", "DSA-q", "DSA",
                                     kop_params[2].data(), static_cast<int>(kop_params[2].size()),
                                     nullptr, 0, nullptr, 0);
            }
            if (kop_params.size() > 3 && !kop_params[3].empty()) {
                ndjson_log_key_event(SURFACE, "CIOCKEY", "DSA-g", "DSA",
                                     kop_params[3].data(), static_cast<int>(kop_params[3].size()),
                                     nullptr, 0, nullptr, 0);
            }
            if (kop_params.size() > 4 && !kop_params[4].empty()) {
                const char* key_type = (kop_before.crk_op == CRK_DSA_SIGN) ? "DSA-private" : "DSA-public";
                ndjson_log_key_event(SURFACE, "CIOCKEY", key_type, "DSA",
                                     kop_params[4].data(), static_cast<int>(kop_params[4].size()),
                                     nullptr, 0, nullptr, 0);
            }
        } else if (kop_before.crk_op == CRK_ECDSA_SIGN || kop_before.crk_op == CRK_ECDSA_VERIFY) {
            // ECDSA operations: digest and EC parameters
            const unsigned char* digest_ptr = kop_params.size() > 0 && !kop_params[0].empty() ? kop_params[0].data() : nullptr;
            int digest_len = kop_params.size() > 0 ? static_cast<int>(kop_params[0].size()) : 0;

            const unsigned char* key_ptr = kop_params.size() > 1 && !kop_params[1].empty() ? kop_params[1].data() : nullptr;
            int key_len = kop_params.size() > 1 ? static_cast<int>(kop_params[1].size()) : 0;

            ndjson_log_key_event(
                SURFACE,
                "CIOCKEY",
                op_name,
                "ECDSA",
                key_ptr,      // EC key as key
                key_len,
                digest_ptr,   // Message digest as IV
                digest_len,
                nullptr, 0);
        } else {
            // Generic handling for other operations
            const unsigned char* keyptr = kop_params[0].empty() ? nullptr : kop_params[0].data();
            int keylen = static_cast<int>(kop_params[0].size());
            ndjson_log_key_event(
                SURFACE,
                "CIOCKEY",
                op_name,
                op_name,
                keyptr,
                keylen,
                nullptr,
                0,
                nullptr,
                0);
        }
    } else if (request == CIOCFSESSION && arg) {
        uint32_t ses = *static_cast<uint32_t*>(arg);
        forget_session(ses);
    }

    return ret;
}
