// src/Linux/hooks/hook_cryptodev.cpp
// Intercept /dev/crypto session creation to capture symmetric keys set via cryptodev.

#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#if !__has_include(<crypto/cryptodev.h>)
#  error "cryptodev support requested but <crypto/cryptodev.h> is not available"
#endif

#include <crypto/cryptodev.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <algorithm>

static constexpr const char* SURFACE = "cryptodev";

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

static const char* kop_op_to_string(unsigned int op) {
    switch (op) {
        case CRK_MOD_EXP: return "CRK_MOD_EXP";
        case CRK_MOD_EXP_CRT: return "CRK_MOD_EXP_CRT";
        case CRK_MOD_INV: return "CRK_MOD_INV";
        case CRK_DSA_SIGN: return "CRK_DSA_SIGN";
        case CRK_DSA_VERIFY: return "CRK_DSA_VERIFY";
        case CRK_DH_COMPUTE_KEY: return "CRK_DH_COMPUTE_KEY";
        case CRK_RSA_SIGN: return "CRK_RSA_SIGN";
        case CRK_RSA_VERIFY: return "CRK_RSA_VERIFY";
        default: return "CRK_UNKNOWN";
    }
}

static std::vector<unsigned char> copy_param(const struct crparam& p) {
    if (!p.crp_p || p.crp_n == 0) return {};
    size_t len = std::min<size_t>(p.crp_n, 1024);
    std::vector<unsigned char> out(len);
    memcpy(out.data(), p.crp_p, len);
    return out;
}

extern "C" int ioctl(int fd, unsigned long request, void* arg) {
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
    if (ret != 0)
        return ret;

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
    } else if (request == CIOCFSESSION && arg) {
        uint32_t ses = *static_cast<uint32_t*>(arg);
        forget_session(ses);
    }

    return ret;
}
