// src/hooks/hook_openssl_ecc.cpp
#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/bn.h>

#include <vector>

#define RESOLVE_SYM(var, name) do { if (!(var)) (var) = (decltype(var))resolve_next_symbol(name); } while (0)
static constexpr const char* SURFACE = "openssl";

namespace {

static inline const char* curve_name(const EC_KEY* key) {
    if (!key) return nullptr;
    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (!group) return nullptr;
    int nid = EC_GROUP_get_curve_name(group);
    return nid != NID_undef ? OBJ_nid2sn(nid) : nullptr;
}

static std::vector<unsigned char> bn_to_bytes(const BIGNUM* bn) {
    std::vector<unsigned char> buf;
    if (!bn) return buf;
    int len = BN_num_bytes(bn);
    if (len <= 0) return buf;
    buf.resize((size_t)len);
    BN_bn2bin(bn, buf.data());
    return buf;
}

static void log_ecdsa_signature(const char* api,
                                EC_KEY* key,
                                const unsigned char* digest,
                                int digest_len,
                                const ECDSA_SIG* sig) {
    std::vector<unsigned char> priv_bytes;
    if (key) {
        const BIGNUM* priv = EC_KEY_get0_private_key(key);
        priv_bytes = bn_to_bytes(priv);
    }

    std::vector<unsigned char> digest_buf;
    if (digest && digest_len > 0) {
        digest_buf.assign(digest, digest + digest_len);
    }

    std::vector<unsigned char> tag_buf;
    if (sig) {
        const BIGNUM *r = nullptr, *s = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        ECDSA_SIG_get0(sig, &r, &s);
#else
        r = sig ? sig->r : nullptr;
        s = sig ? sig->s : nullptr;
#endif
        auto r_bytes = bn_to_bytes(r);
        auto s_bytes = bn_to_bytes(s);
        if (!r_bytes.empty() || !s_bytes.empty()) {
            tag_buf.reserve(r_bytes.size() + s_bytes.size());
            tag_buf.insert(tag_buf.end(), r_bytes.begin(), r_bytes.end());
            tag_buf.insert(tag_buf.end(), s_bytes.begin(), s_bytes.end());
        }
    }

    ndjson_log_key_event(
        SURFACE,
        api,
        "sign",
        curve_name(key),
        priv_bytes.empty() ? nullptr : priv_bytes.data(),
        (int)priv_bytes.size(),
        digest_buf.empty() ? nullptr : digest_buf.data(),
        (int)digest_buf.size(),
        tag_buf.empty() ? nullptr : tag_buf.data(),
        (int)tag_buf.size());
}

} // namespace

using fn_EC_KEY_generate_key = int(*)(EC_KEY*);
static fn_EC_KEY_generate_key real_EC_KEY_generate_key = nullptr;

extern "C" int EC_KEY_generate_key(EC_KEY* key) {
    RESOLVE_SYM(real_EC_KEY_generate_key, "EC_KEY_generate_key");
    if (!real_EC_KEY_generate_key) return 0;
    ReentryGuard guard;
    if (!guard) return real_EC_KEY_generate_key(key);
    int ret = real_EC_KEY_generate_key(key);
    if (ret == 1) {
        std::vector<unsigned char> priv_bytes;
        if (key) {
            priv_bytes = bn_to_bytes(EC_KEY_get0_private_key(key));
        }
        if (!priv_bytes.empty()) {
            ndjson_log_key_event(
                SURFACE,
                "EC_KEY_generate_key",
                "gen",
                curve_name(key),
                priv_bytes.data(),
                (int)priv_bytes.size(),
                nullptr,
                0,
                nullptr,
                0);
        }
    }
    return ret;
}

using fn_ECDSA_do_sign = ECDSA_SIG*(*)(const unsigned char*, int, EC_KEY*);
static fn_ECDSA_do_sign real_ECDSA_do_sign = nullptr;

extern "C" ECDSA_SIG* ECDSA_do_sign(const unsigned char* digest, int digest_len, EC_KEY* key) {
    RESOLVE_SYM(real_ECDSA_do_sign, "ECDSA_do_sign");
    if (!real_ECDSA_do_sign) return nullptr;
    ReentryGuard guard;
    if (!guard) return real_ECDSA_do_sign(digest, digest_len, key);
    ECDSA_SIG* sig = real_ECDSA_do_sign(digest, digest_len, key);
    if (sig) {
        log_ecdsa_signature("ECDSA_do_sign", key, digest, digest_len, sig);
    }
    return sig;
}

using fn_ECDSA_do_sign_ex = ECDSA_SIG*(*)(const unsigned char*, int, const BIGNUM*, const BIGNUM*, EC_KEY*);
static fn_ECDSA_do_sign_ex real_ECDSA_do_sign_ex = nullptr;

extern "C" ECDSA_SIG* ECDSA_do_sign_ex(const unsigned char* digest, int digest_len,
                                       const BIGNUM* kinv, const BIGNUM* r, EC_KEY* key) {
    RESOLVE_SYM(real_ECDSA_do_sign_ex, "ECDSA_do_sign_ex");
    if (!real_ECDSA_do_sign_ex) return nullptr;
    ReentryGuard guard;
    if (!guard) return real_ECDSA_do_sign_ex(digest, digest_len, kinv, r, key);
    ECDSA_SIG* sig = real_ECDSA_do_sign_ex(digest, digest_len, kinv, r, key);
    if (sig) {
        log_ecdsa_signature("ECDSA_do_sign_ex", key, digest, digest_len, sig);
    }
    return sig;
}

using fn_ECDSA_sign = int(*)(int, const unsigned char*, int, unsigned char*, unsigned int*, EC_KEY*);
static fn_ECDSA_sign real_ECDSA_sign = nullptr;

extern "C" int ECDSA_sign(int type, const unsigned char* digest, int digest_len,
                          unsigned char* sig, unsigned int* sig_len, EC_KEY* key) {
    RESOLVE_SYM(real_ECDSA_sign, "ECDSA_sign");
    if (!real_ECDSA_sign) return 0;
    ReentryGuard guard;
    if (!guard) return real_ECDSA_sign(type, digest, digest_len, sig, sig_len, key);
    int ret = real_ECDSA_sign(type, digest, digest_len, sig, sig_len, key);
    if (ret == 1) {
        std::vector<unsigned char> priv_bytes;
        if (key) {
            priv_bytes = bn_to_bytes(EC_KEY_get0_private_key(key));
        }
        ndjson_log_key_event(
            SURFACE,
            "ECDSA_sign",
            "sign",
            curve_name(key),
            priv_bytes.empty() ? nullptr : priv_bytes.data(),
            (int)priv_bytes.size(),
            digest,
            digest_len,
            (sig && sig_len && *sig_len > 0) ? sig : nullptr,
            (sig && sig_len && *sig_len > 0) ? (int)*sig_len : 0);
    }
    return ret;
}
