// src/Linux/hooks/hook_mbedtls.cpp
// Intercept selected mbedTLS primitives to capture key material and signatures.

#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#if !__has_include(<mbedtls/gcm.h>) || !__has_include(<mbedtls/md.h>) || !__has_include(<mbedtls/pk.h>)
#error "hook_mbedtls.cpp requires mbedTLS headers"
#endif

#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>

#if defined(MBEDTLS_RSA_C)
#include <mbedtls/rsa.h>
#endif
#if defined(MBEDTLS_ECP_C)
#include <mbedtls/ecp.h>
#endif
#if defined(MBEDTLS_ECDSA_C)
#include <mbedtls/ecdsa.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

static constexpr const char* SURFACE = "mbedtls";

#define RESOLVE_SYM(var, name)                                                     \
    do {                                                                           \
        if (!(var)) {                                                              \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(name));    \
        }                                                                          \
    } while (0)

namespace {

constexpr size_t kMaxHashSnapshot = 256;
constexpr size_t kMaxSignatureSnapshot = 1024;
constexpr size_t kMaxTagSnapshot = 128;

struct GcmState {
    std::string cipher_name;
    std::vector<unsigned char> key;
};

static std::mutex g_gcm_mu;
static std::unordered_map<const mbedtls_gcm_context*, GcmState> g_gcm_states;

static std::mutex g_hmac_mu;
struct HmacState {
    std::string hash_name;
    std::vector<unsigned char> key;
};
static std::unordered_map<const mbedtls_md_context_t*, HmacState> g_hmac_states;

static std::string describe_gcm_cipher(mbedtls_cipher_id_t cipher, unsigned int keybits) {
    std::string name;
    switch (cipher) {
        case MBEDTLS_CIPHER_ID_AES:
            name = "AES-GCM";
            break;
        case MBEDTLS_CIPHER_ID_CAMELLIA:
            name = "CAMELLIA-GCM";
            break;
        default:
            name = "GCM";
            break;
    }
    if (keybits > 0) {
        name += '-';
        name += std::to_string(keybits);
    }
    return name;
}

static std::vector<unsigned char> mpi_to_bytes(const mbedtls_mpi& mpi) {
    if (mpi.n == 0 || mpi.p == nullptr) {
        return {};
    }

    size_t limbs = mpi.n;
    while (limbs > 0 && mpi.p[limbs - 1] == 0) {
        --limbs;
    }
    if (limbs == 0) {
        return {0};
    }

    const size_t limb_bytes = sizeof(mbedtls_mpi_uint);
    const size_t total = limbs * limb_bytes;
    std::vector<unsigned char> buf(total, 0);
    for (size_t i = 0; i < limbs; ++i) {
        mbedtls_mpi_uint limb = mpi.p[i];
        for (size_t j = 0; j < limb_bytes; ++j) {
            const size_t idx = total - (i * limb_bytes + j) - 1;
            buf[idx] = static_cast<unsigned char>(limb & 0xFFu);
            limb >>= 8;
        }
    }

    size_t offset = 0;
    while (offset < buf.size() && buf[offset] == 0) {
        ++offset;
    }
    if (offset >= buf.size()) {
        return {0};
    }
    return std::vector<unsigned char>(buf.begin() + static_cast<std::ptrdiff_t>(offset), buf.end());
}

#if defined(MBEDTLS_ECP_C)
static const char* curve_id_to_name(mbedtls_ecp_group_id id) {
    switch (id) {
        case MBEDTLS_ECP_DP_SECP192R1: return "secp192r1";
        case MBEDTLS_ECP_DP_SECP224R1: return "secp224r1";
        case MBEDTLS_ECP_DP_SECP256R1: return "secp256r1";
        case MBEDTLS_ECP_DP_SECP384R1: return "secp384r1";
        case MBEDTLS_ECP_DP_SECP521R1: return "secp521r1";
        case MBEDTLS_ECP_DP_BP256R1:   return "brainpoolP256r1";
        case MBEDTLS_ECP_DP_BP384R1:   return "brainpoolP384r1";
        case MBEDTLS_ECP_DP_BP512R1:   return "brainpoolP512r1";
        case MBEDTLS_ECP_DP_SECP256K1: return "secp256k1";
        case MBEDTLS_ECP_DP_CURVE25519: return "curve25519";
        case MBEDTLS_ECP_DP_CURVE448:   return "curve448";
        default: return "ec-unknown";
    }
}
#endif

static std::vector<unsigned char> copy_buffer_limited(const unsigned char* data,
                                                       size_t len,
                                                       size_t max_len) {
    if (!data || len == 0) {
        return {};
    }
    size_t copy_len = std::min(len, max_len);
    std::vector<unsigned char> out(copy_len);
    std::memcpy(out.data(), data, copy_len);
    return out;
}

static void remember_gcm_state(const mbedtls_gcm_context* ctx,
                               const std::string& cipher_name,
                               const unsigned char* key,
                               size_t key_len) {
    if (!ctx || !key || key_len == 0) {
        return;
    }
    GcmState state;
    state.cipher_name = cipher_name;
    state.key.assign(key, key + key_len);
    std::lock_guard<std::mutex> lock(g_gcm_mu);
    g_gcm_states[ctx] = std::move(state);
}

static GcmState lookup_gcm_state(const mbedtls_gcm_context* ctx) {
    std::lock_guard<std::mutex> lock(g_gcm_mu);
    auto it = g_gcm_states.find(ctx);
    if (it != g_gcm_states.end()) {
        return it->second;
    }
    return {};
}

static void forget_gcm_state(const mbedtls_gcm_context* ctx) {
    std::lock_guard<std::mutex> lock(g_gcm_mu);
    g_gcm_states.erase(ctx);
}

static void remember_hmac_state(const mbedtls_md_context_t* ctx,
                                const char* hash_name,
                                const unsigned char* key,
                                size_t key_len) {
    if (!ctx || !hash_name || !key || key_len == 0) {
        return;
    }
    HmacState state;
    state.hash_name = hash_name;
    state.key.assign(key, key + key_len);
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    g_hmac_states[ctx] = std::move(state);
}

static std::optional<HmacState> lookup_hmac_state(const mbedtls_md_context_t* ctx) {
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    auto it = g_hmac_states.find(ctx);
    if (it != g_hmac_states.end()) {
        return it->second;
    }
    return std::nullopt;
}

static void forget_hmac_state(const mbedtls_md_context_t* ctx) {
    std::lock_guard<std::mutex> lock(g_hmac_mu);
    g_hmac_states.erase(ctx);
}

static void log_gcm_event(const char* api,
                           const GcmState& state,
                           const char* direction,
                           const unsigned char* iv,
                           size_t iv_len,
                           const unsigned char* tag,
                           size_t tag_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        state.cipher_name.empty() ? nullptr : state.cipher_name.c_str(),
        state.key.empty() ? nullptr : state.key.data(),
        static_cast<int>(state.key.size()),
        iv && iv_len ? iv : nullptr,
        static_cast<int>(iv_len),
        tag && tag_len ? tag : nullptr,
        static_cast<int>(tag_len));
}

static void log_hmac_event(const char* api,
                            const HmacState& state,
                            const char* direction,
                            const unsigned char* payload,
                            size_t payload_len) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        state.hash_name.empty() ? nullptr : state.hash_name.c_str(),
        state.key.empty() ? nullptr : state.key.data(),
        static_cast<int>(state.key.size()),
        payload && payload_len ? payload : nullptr,
        static_cast<int>(payload_len),
        nullptr,
        0);
}

static void log_pk_sign_event(const char* cipher_name,
                              const std::vector<unsigned char>& priv_key,
                              const std::vector<unsigned char>& hash_snapshot,
                              const std::vector<unsigned char>& signature) {
    ndjson_log_key_event(
        SURFACE,
        "mbedtls_pk_sign",
        "sign",
        cipher_name && cipher_name[0] ? cipher_name : nullptr,
        priv_key.empty() ? nullptr : priv_key.data(),
        static_cast<int>(priv_key.size()),
        hash_snapshot.empty() ? nullptr : hash_snapshot.data(),
        static_cast<int>(hash_snapshot.size()),
        signature.empty() ? nullptr : signature.data(),
        static_cast<int>(signature.size()));
}

static std::vector<unsigned char> snapshot_hash(const unsigned char* hash,
                                                size_t len) {
    return copy_buffer_limited(hash, len, kMaxHashSnapshot);
}

static std::vector<unsigned char> snapshot_signature(const unsigned char* sig,
                                                     size_t len) {
    return copy_buffer_limited(sig, len, kMaxSignatureSnapshot);
}

} // namespace

extern "C" {

typedef int (*fn_mbedtls_gcm_setkey)(mbedtls_gcm_context*, mbedtls_cipher_id_t,
                                     const unsigned char*, unsigned int);
static fn_mbedtls_gcm_setkey real_mbedtls_gcm_setkey = nullptr;

int mbedtls_gcm_setkey(mbedtls_gcm_context* ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char* key,
                       unsigned int keybits) {
    RESOLVE_SYM(real_mbedtls_gcm_setkey, "mbedtls_gcm_setkey");
    if (!real_mbedtls_gcm_setkey) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_gcm_setkey(ctx, cipher, key, keybits);
    }

    int ret = real_mbedtls_gcm_setkey(ctx, cipher, key, keybits);
    if (ret == 0 && ctx && key && keybits % 8 == 0) {
        const size_t key_len = static_cast<size_t>(keybits / 8);
        auto cipher_name = describe_gcm_cipher(cipher, keybits);
        remember_gcm_state(ctx, cipher_name, key, key_len);
        ndjson_log_key_event(
            SURFACE,
            "mbedtls_gcm_setkey",
            "setkey",
            cipher_name.empty() ? nullptr : cipher_name.c_str(),
            key,
            static_cast<int>(key_len),
            nullptr,
            0,
            nullptr,
            0);
    }
    return ret;
}

typedef void (*fn_mbedtls_gcm_free)(mbedtls_gcm_context*);
static fn_mbedtls_gcm_free real_mbedtls_gcm_free = nullptr;

void mbedtls_gcm_free(mbedtls_gcm_context* ctx) {
    RESOLVE_SYM(real_mbedtls_gcm_free, "mbedtls_gcm_free");
    if (!real_mbedtls_gcm_free) {
        return;
    }

    forget_gcm_state(ctx);

    ReentryGuard guard;
    if (!guard) {
        real_mbedtls_gcm_free(ctx);
        return;
    }
    real_mbedtls_gcm_free(ctx);
}

typedef int (*fn_mbedtls_gcm_crypt_and_tag)(mbedtls_gcm_context*, int, size_t,
                                            const unsigned char*, size_t,
                                            const unsigned char*, size_t,
                                            const unsigned char*, unsigned char*,
                                            size_t, unsigned char*);
static fn_mbedtls_gcm_crypt_and_tag real_mbedtls_gcm_crypt_and_tag = nullptr;

int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context* ctx,
                              int mode,
                              size_t length,
                              const unsigned char* iv,
                              size_t iv_len,
                              const unsigned char* add,
                              size_t add_len,
                              const unsigned char* input,
                              unsigned char* output,
                              size_t tag_len,
                              unsigned char* tag) {
    RESOLVE_SYM(real_mbedtls_gcm_crypt_and_tag, "mbedtls_gcm_crypt_and_tag");
    if (!real_mbedtls_gcm_crypt_and_tag) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_gcm_crypt_and_tag(ctx, mode, length, iv, iv_len,
                                              add, add_len, input, output,
                                              tag_len, tag);
    }

    int ret = real_mbedtls_gcm_crypt_and_tag(ctx, mode, length, iv, iv_len,
                                             add, add_len, input, output,
                                             tag_len, tag);
    if (ret == 0) {
        auto state = lookup_gcm_state(ctx);
        const char* dir = (mode == MBEDTLS_GCM_ENCRYPT) ? "enc" : "dec";
        const size_t capped_tag_len = std::min(tag_len, kMaxTagSnapshot);
        log_gcm_event("mbedtls_gcm_crypt_and_tag",
                      state,
                      dir,
                      iv,
                      iv_len,
                      tag,
                      capped_tag_len);
    }
    (void)length;
    (void)add;
    (void)add_len;
    (void)input;
    (void)output;
    return ret;
}

typedef int (*fn_mbedtls_gcm_auth_decrypt)(mbedtls_gcm_context*, size_t,
                                           const unsigned char*, size_t,
                                           const unsigned char*, size_t,
                                           const unsigned char*, size_t,
                                           const unsigned char*, unsigned char*);
static fn_mbedtls_gcm_auth_decrypt real_mbedtls_gcm_auth_decrypt = nullptr;

int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context* ctx,
                             size_t length,
                             const unsigned char* iv,
                             size_t iv_len,
                             const unsigned char* add,
                             size_t add_len,
                             const unsigned char* tag,
                             size_t tag_len,
                             const unsigned char* input,
                             unsigned char* output) {
    RESOLVE_SYM(real_mbedtls_gcm_auth_decrypt, "mbedtls_gcm_auth_decrypt");
    if (!real_mbedtls_gcm_auth_decrypt) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_gcm_auth_decrypt(ctx, length, iv, iv_len, add, add_len,
                                             tag, tag_len, input, output);
    }

    int ret = real_mbedtls_gcm_auth_decrypt(ctx, length, iv, iv_len, add, add_len,
                                            tag, tag_len, input, output);
    if (ret == 0) {
        auto state = lookup_gcm_state(ctx);
        const size_t capped_tag_len = std::min(tag_len, kMaxTagSnapshot);
        log_gcm_event("mbedtls_gcm_auth_decrypt",
                      state,
                      "dec",
                      iv,
                      iv_len,
                      tag,
                      capped_tag_len);
    }
    (void)length;
    (void)add;
    (void)add_len;
    (void)input;
    (void)output;
    return ret;
}

typedef int (*fn_mbedtls_md_hmac_starts)(mbedtls_md_context_t*, const unsigned char*, size_t);
static fn_mbedtls_md_hmac_starts real_mbedtls_md_hmac_starts = nullptr;

typedef int (*fn_mbedtls_md_hmac_finish)(mbedtls_md_context_t*, unsigned char*);
static fn_mbedtls_md_hmac_finish real_mbedtls_md_hmac_finish = nullptr;

typedef void (*fn_mbedtls_md_free)(mbedtls_md_context_t*);
static fn_mbedtls_md_free real_mbedtls_md_free = nullptr;

int mbedtls_md_hmac_starts(mbedtls_md_context_t* ctx,
                           const unsigned char* key,
                           size_t keylen) {
    RESOLVE_SYM(real_mbedtls_md_hmac_starts, "mbedtls_md_hmac_starts");
    if (!real_mbedtls_md_hmac_starts) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_md_hmac_starts(ctx, key, keylen);
    }

    int ret = real_mbedtls_md_hmac_starts(ctx, key, keylen);
    if (ret == 0 && ctx && ctx->md_info && key && keylen > 0) {
        remember_hmac_state(ctx, ctx->md_info->name, key, keylen);
        HmacState snapshot{ctx->md_info->name, std::vector<unsigned char>(key, key + keylen)};
        log_hmac_event("mbedtls_md_hmac_starts", snapshot, "init", nullptr, 0);
    }
    return ret;
}

int mbedtls_md_hmac_finish(mbedtls_md_context_t* ctx, unsigned char* output) {
    RESOLVE_SYM(real_mbedtls_md_hmac_finish, "mbedtls_md_hmac_finish");
    if (!real_mbedtls_md_hmac_finish) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_md_hmac_finish(ctx, output);
    }

    int ret = real_mbedtls_md_hmac_finish(ctx, output);
    if (ret == 0 && ctx && output) {
        auto maybe_state = lookup_hmac_state(ctx);
        if (maybe_state.has_value()) {
            auto tag_snapshot = copy_buffer_limited(output,
                                                    static_cast<size_t>(ctx->md_info ? ctx->md_info->size : 0),
                                                    kMaxTagSnapshot);
            ndjson_log_key_event(
                SURFACE,
                "mbedtls_md_hmac_finish",
                "final",
                maybe_state->hash_name.c_str(),
                maybe_state->key.empty() ? nullptr : maybe_state->key.data(),
                static_cast<int>(maybe_state->key.size()),
                nullptr,
                0,
                tag_snapshot.empty() ? nullptr : tag_snapshot.data(),
                static_cast<int>(tag_snapshot.size()));
        }
    }
    return ret;
}

void mbedtls_md_free(mbedtls_md_context_t* ctx) {
    RESOLVE_SYM(real_mbedtls_md_free, "mbedtls_md_free");
    if (!real_mbedtls_md_free) {
        return;
    }

    forget_hmac_state(ctx);

    ReentryGuard guard;
    if (!guard) {
        real_mbedtls_md_free(ctx);
        return;
    }
    real_mbedtls_md_free(ctx);
}

typedef int (*fn_mbedtls_pk_sign)(mbedtls_pk_context*, mbedtls_md_type_t,
                                  const unsigned char*, size_t,
                                  unsigned char*, size_t*,
                                  int (*)(void*, unsigned char*, size_t),
                                  void*);
static fn_mbedtls_pk_sign real_mbedtls_pk_sign = nullptr;

int mbedtls_pk_sign(mbedtls_pk_context* ctx,
                    mbedtls_md_type_t md_alg,
                    const unsigned char* hash,
                    size_t hash_len,
                    unsigned char* sig,
                    size_t* sig_len,
                    int (*f_rng)(void*, unsigned char*, size_t),
                    void* p_rng) {
    RESOLVE_SYM(real_mbedtls_pk_sign, "mbedtls_pk_sign");
    if (!real_mbedtls_pk_sign) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_mbedtls_pk_sign(ctx, md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng);
    }

    int ret = real_mbedtls_pk_sign(ctx, md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng);
    if (ret == 0 && ctx && ctx->pk_info && ctx->pk_ctx && sig && sig_len && *sig_len > 0) {
        std::vector<unsigned char> priv_bytes;
        const char* cipher_name = ctx->pk_info->name;

        switch (ctx->pk_info->type) {
#if defined(MBEDTLS_RSA_C)
            case MBEDTLS_PK_RSA: {
                const auto* rsa = static_cast<const mbedtls_rsa_context*>(ctx->pk_ctx);
                if (rsa) {
                    priv_bytes = mpi_to_bytes(rsa->D);
                }
                if (ctx->pk_info->get_bitlen && cipher_name) {
                    size_t bits = ctx->pk_info->get_bitlen(ctx->pk_ctx);
                    if (bits > 0) {
                        // Append bit length for clarity, e.g., "RSA-2048".
                        static thread_local std::string rsa_name;
                        rsa_name.assign("RSA-");
                        rsa_name += std::to_string(bits);
                        cipher_name = rsa_name.c_str();
                    }
                }
                break;
            }
#endif
#if defined(MBEDTLS_ECP_C)
            case MBEDTLS_PK_ECKEY:
            case MBEDTLS_PK_ECKEY_DH:
            case MBEDTLS_PK_ECDSA: {
                const auto* keypair = static_cast<const mbedtls_ecp_keypair*>(ctx->pk_ctx);
                if (keypair) {
                    priv_bytes = mpi_to_bytes(keypair->d);
                    cipher_name = curve_id_to_name(keypair->grp.id);
                }
                break;
            }
#endif
            default:
                break;
        }

        auto hash_snapshot = snapshot_hash(hash, hash_len);
        auto sig_snapshot = snapshot_signature(sig, *sig_len);
        log_pk_sign_event(cipher_name, priv_bytes, hash_snapshot, sig_snapshot);
    }

    return ret;
}

} // extern "C"
