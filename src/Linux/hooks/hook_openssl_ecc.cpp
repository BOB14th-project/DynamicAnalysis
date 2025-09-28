// src/hooks/hook_openssl_ecc.cpp
#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include <vector>
#include <string>
#include <algorithm>

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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static bool extract_ec_key_info(EVP_PKEY* pkey,
                                std::vector<unsigned char>& priv_out,
                                std::string& curve_out) {
    priv_out.clear();
    curve_out.clear();
    if (!pkey) return false;
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) return false;

    char curve_buf[128];
    size_t curve_len = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey,
                                       OSSL_PKEY_PARAM_GROUP_NAME,
                                       curve_buf,
                                       sizeof(curve_buf),
                                       &curve_len) > 0 &&
        curve_len > 0 && curve_len < sizeof(curve_buf)) {
        curve_out.assign(curve_buf, curve_len);
    }

    BIGNUM* priv_bn = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) > 0 && priv_bn) {
        priv_out = bn_to_bytes(priv_bn);
        BN_free(priv_bn);
    }

    return true;
}

static std::vector<unsigned char> snapshot_digest(EVP_MD_CTX* ctx) {
    std::vector<unsigned char> digest;
    if (!ctx) return digest;
    EVP_MD_CTX* tmp = EVP_MD_CTX_new();
    if (!tmp) return digest;
    if (EVP_MD_CTX_copy_ex(tmp, ctx) <= 0) {
        EVP_MD_CTX_free(tmp);
        return digest;
    }
    unsigned int len = 0;
    digest.resize(EVP_MAX_MD_SIZE);
    if (EVP_DigestFinal_ex(tmp, digest.data(), &len) <= 0) {
        digest.clear();
    } else {
        digest.resize(len);
    }
    EVP_MD_CTX_free(tmp);
    return digest;
}

static EVP_PKEY* md_ctx_get0_pkey(EVP_MD_CTX* ctx) {
    if (!ctx) return nullptr;
    EVP_PKEY_CTX* pctx = EVP_MD_CTX_pkey_ctx(ctx);
    return pctx ? EVP_PKEY_CTX_get0_pkey(pctx) : nullptr;
}

static std::vector<unsigned char> ecdsa_der_to_rs(const unsigned char* sig, size_t sig_len) {
    std::vector<unsigned char> combined;
    if (!sig || sig_len == 0) return combined;
    const unsigned char* p = sig;
    ECDSA_SIG* ec_sig = d2i_ECDSA_SIG(nullptr, &p, sig_len);
    if (!ec_sig) return combined;
    const BIGNUM *r = nullptr, *s = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ECDSA_SIG_get0(ec_sig, &r, &s);
#else
    r = ec_sig->r;
    s = ec_sig->s;
#endif
    auto r_bytes = bn_to_bytes(r);
    auto s_bytes = bn_to_bytes(s);
    combined.reserve(r_bytes.size() + s_bytes.size());
    combined.insert(combined.end(), r_bytes.begin(), r_bytes.end());
    combined.insert(combined.end(), s_bytes.begin(), s_bytes.end());
    ECDSA_SIG_free(ec_sig);
    return combined;
}

#endif // OPENSSL_VERSION_NUMBER >= 0x30000000L

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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

using fn_EVP_PKEY_keygen = int(*)(EVP_PKEY_CTX*, EVP_PKEY**);
static fn_EVP_PKEY_keygen real_EVP_PKEY_keygen = nullptr;

extern "C" int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey) {
    RESOLVE_SYM(real_EVP_PKEY_keygen, "EVP_PKEY_keygen");
    if (!real_EVP_PKEY_keygen) return 0;
    ReentryGuard guard;
    if (!guard) return real_EVP_PKEY_keygen(ctx, ppkey);
    int ret = real_EVP_PKEY_keygen(ctx, ppkey);
    if (ret > 0 && ppkey && *ppkey) {
        std::vector<unsigned char> priv;
        std::string curve;
        if (extract_ec_key_info(*ppkey, priv, curve) && !priv.empty()) {
            ndjson_log_key_event(
                SURFACE,
                "EVP_PKEY_keygen",
                "gen",
                curve.empty() ? nullptr : curve.c_str(),
                priv.data(),
                (int)priv.size(),
                nullptr,
                0,
                nullptr,
                0);
        }
    }
    return ret;
}

using fn_EVP_DigestSignFinal = int(*)(EVP_MD_CTX*, unsigned char*, size_t*);
static fn_EVP_DigestSignFinal real_EVP_DigestSignFinal = nullptr;

extern "C" int EVP_DigestSignFinal(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen) {
    RESOLVE_SYM(real_EVP_DigestSignFinal, "EVP_DigestSignFinal");
    if (!real_EVP_DigestSignFinal) return 0;
    ReentryGuard guard;
    if (!guard) return real_EVP_DigestSignFinal(ctx, sigret, siglen);

    std::vector<unsigned char> digest_snapshot;
    EVP_PKEY* preview_key = md_ctx_get0_pkey(ctx);
    if (preview_key && EVP_PKEY_base_id(preview_key) == EVP_PKEY_EC) {
        digest_snapshot = snapshot_digest(ctx);
    }

    int ret = real_EVP_DigestSignFinal(ctx, sigret, siglen);
    if (ret > 0 && ctx && siglen && sigret && *siglen > 0) {
        EVP_PKEY* pkey = md_ctx_get0_pkey(ctx);
        std::vector<unsigned char> priv;
        std::string curve;
        if (extract_ec_key_info(pkey, priv, curve) && (!priv.empty() || !curve.empty())) {
            auto rs = ecdsa_der_to_rs(sigret, *siglen);
            ndjson_log_key_event(
                SURFACE,
                "EVP_DigestSignFinal",
                "sign",
                curve.empty() ? nullptr : curve.c_str(),
                priv.empty() ? nullptr : priv.data(),
                (int)priv.size(),
                digest_snapshot.empty() ? nullptr : digest_snapshot.data(),
                (int)digest_snapshot.size(),
                rs.empty() ? sigret : rs.data(),
                rs.empty() ? (int)*siglen : (int)rs.size());
        }
    }
    return ret;
}

#endif // OPENSSL_VERSION_NUMBER >= 0x30000000L
