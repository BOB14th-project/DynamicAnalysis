// src/Linux/hooks/hook_nss.cpp
// Intercepts key import and encryption/decryption through Mozilla NSS PK11 APIs
// to expose symmetric material via NDJSON logging.

#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#if !__has_include(<nss/nss.h>) || !__has_include(<nss/pk11pub.h>)
#error "hook_nss.cpp requires NSS development headers"
#endif

#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nspr/prio.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

static constexpr const char* SURFACE = "nss";

#define RESOLVE_SYM(var, name_literal)                                               \
    do {                                                                             \
        if (!(var)) {                                                                \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(name_literal)); \
        }                                                                            \
    } while (0)

namespace {

struct SymKeyInfo {
    CK_MECHANISM_TYPE mechanism;
    std::vector<unsigned char> key_bytes;
};

static std::mutex g_symkey_mu;
static std::unordered_map<PK11SymKey*, SymKeyInfo> g_symkey_map;

constexpr size_t kMaxSnapshot = 512;

static std::string mechanism_to_string(CK_MECHANISM_TYPE mech) {
    switch (mech) {
        case CKM_AES_GCM: return "AES-GCM";
        case CKM_AES_CBC: return "AES-CBC";
        case CKM_AES_CBC_PAD: return "AES-CBC-PAD";
        case CKM_AES_CTR: return "AES-CTR";
        case CKM_DES3_CBC: return "3DES-CBC";
        default: break;
    }
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "mech-0x%lx", static_cast<unsigned long>(mech));
    return std::string(buffer);
}

static void remember_symkey(PK11SymKey* key,
                             CK_MECHANISM_TYPE mech,
                             const SECItem* key_item) {
    if (!key) {
        return;
    }
    SymKeyInfo info;
    info.mechanism = mech;
    if (key_item && key_item->data && key_item->len > 0) {
        size_t copy_len = std::min(static_cast<size_t>(key_item->len), kMaxSnapshot);
        info.key_bytes.assign(key_item->data, key_item->data + static_cast<int>(copy_len));
    }

    std::lock_guard<std::mutex> lock(g_symkey_mu);
    g_symkey_map[key] = std::move(info);
}

static std::optional<SymKeyInfo> fetch_symkey(PK11SymKey* key) {
    std::lock_guard<std::mutex> lock(g_symkey_mu);
    auto it = g_symkey_map.find(key);
    if (it == g_symkey_map.end()) {
        return std::nullopt;
    }
    return it->second;
}

static void forget_symkey(PK11SymKey* key) {
    std::lock_guard<std::mutex> lock(g_symkey_mu);
    g_symkey_map.erase(key);
}

static std::vector<unsigned char> copy_buffer(const void* data, size_t len) {
    if (!data || len == 0) {
        return {};
    }
    size_t copy_len = std::min(len, kMaxSnapshot);
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    return std::vector<unsigned char>(bytes, bytes + static_cast<std::ptrdiff_t>(copy_len));
}

static void log_event(const char* api,
                      const char* direction,
                      const SymKeyInfo& info,
                      const unsigned char* iv,
                      size_t iv_len,
                      const unsigned char* tag,
                      size_t tag_len) {
    std::string cipher_name = mechanism_to_string(info.mechanism);
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        cipher_name.c_str(),
        info.key_bytes.empty() ? nullptr : info.key_bytes.data(),
        static_cast<int>(info.key_bytes.size()),
        iv && iv_len ? iv : nullptr,
        static_cast<int>(iv_len),
        tag && tag_len ? tag : nullptr,
        static_cast<int>(tag_len));
}

static void extract_iv_and_tag(CK_MECHANISM_TYPE mech,
                               const SECItem* param,
                               std::vector<unsigned char>& iv_out,
                               std::vector<unsigned char>& tag_out) {
    iv_out.clear();
    tag_out.clear();
    if (!param || !param->data || param->len == 0) {
        return;
    }

    if (mech == CKM_AES_GCM && param->len >= sizeof(CK_GCM_PARAMS)) {
        const CK_GCM_PARAMS* gcm = reinterpret_cast<const CK_GCM_PARAMS*>(param->data);
        iv_out = copy_buffer(gcm->pIv, gcm->ulIvLen);
        // NSS appends authentication tag to ciphertext; parameters only carry lengths.
        // Log tag length as metadata, but actual tag captured from ciphertext later if needed.
        if (gcm->ulTagBits >= 8) {
            size_t tag_len = std::min(static_cast<size_t>(gcm->ulTagBits / 8), kMaxSnapshot);
            tag_out.resize(tag_len, 0);
        }
        return;
    }

    if ((mech == CKM_AES_CBC || mech == CKM_AES_CBC_PAD) && param->len > 0) {
        iv_out = copy_buffer(param->data, param->len);
        return;
    }
}

} // namespace

extern "C" {

typedef PK11SymKey* (*fn_PK11_ImportSymKey)(PK11SlotInfo*, CK_MECHANISM_TYPE,
                                            PK11Origin, CK_ATTRIBUTE_TYPE,
                                            SECItem*, void*);
static fn_PK11_ImportSymKey real_PK11_ImportSymKey = nullptr;

PK11SymKey* PK11_ImportSymKey(PK11SlotInfo* slot,
                              CK_MECHANISM_TYPE mechanism,
                              PK11Origin origin,
                              CK_ATTRIBUTE_TYPE operation,
                              SECItem* key,
                              void* wincx) {
    RESOLVE_SYM(real_PK11_ImportSymKey, "PK11_ImportSymKey");
    if (!real_PK11_ImportSymKey) {
        return nullptr;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_ImportSymKey(slot, mechanism, origin, operation, key, wincx);
    }

    PK11SymKey* sym = real_PK11_ImportSymKey(slot, mechanism, origin, operation, key, wincx);
    if (sym && key) {
        remember_symkey(sym, mechanism, key);
        if (auto info = fetch_symkey(sym)) {
            log_event("PK11_ImportSymKey", "import", *info, nullptr, 0, nullptr, 0);
        }
    }
    return sym;
}

typedef void (*fn_PK11_FreeSymKey)(PK11SymKey*);
static fn_PK11_FreeSymKey real_PK11_FreeSymKey = nullptr;

void PK11_FreeSymKey(PK11SymKey* symKey) {
    RESOLVE_SYM(real_PK11_FreeSymKey, "PK11_FreeSymKey");
    if (!real_PK11_FreeSymKey) {
        return;
    }

    forget_symkey(symKey);

    ReentryGuard guard;
    if (!guard) {
        real_PK11_FreeSymKey(symKey);
        return;
    }
    real_PK11_FreeSymKey(symKey);
}

typedef SECStatus (*fn_PK11_Encrypt)(PK11SymKey*, CK_MECHANISM_TYPE, SECItem*,
                                     unsigned char*, unsigned int*, unsigned int,
                                     const unsigned char*, unsigned int);
static fn_PK11_Encrypt real_PK11_Encrypt = nullptr;

SECStatus PK11_Encrypt(PK11SymKey* symKey,
                      CK_MECHANISM_TYPE mechanism,
                      SECItem* param,
                      unsigned char* out,
                      unsigned int* outLen,
                      unsigned int maxOut,
                      const unsigned char* in,
                      unsigned int inLen) {
    RESOLVE_SYM(real_PK11_Encrypt, "PK11_Encrypt");
    if (!real_PK11_Encrypt) {
        return SECFailure;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_Encrypt(symKey, mechanism, param, out, outLen, maxOut, in, inLen);
    }

    std::vector<unsigned char> iv;
    std::vector<unsigned char> tag_placeholder;

    auto info = fetch_symkey(symKey);
    if (!info.has_value()) {
        remember_symkey(symKey, mechanism, nullptr);
        info = fetch_symkey(symKey);
    }

    if (info.has_value()) {
        extract_iv_and_tag(info->mechanism, param, iv, tag_placeholder);
    }

    SECStatus status = real_PK11_Encrypt(symKey, mechanism, param, out, outLen, maxOut, in, inLen);

    if (info.has_value()) {
        const unsigned char* tag_ptr = nullptr;
        size_t tag_len = 0;
        if (info->mechanism == CKM_AES_GCM && out && outLen && *outLen > inLen) {
            // Assume trailing bytes constitute authentication tag.
            tag_len = std::min(static_cast<size_t>(*outLen - inLen), kMaxSnapshot);
            if (tag_len > 0) {
                tag_ptr = out + (*outLen - tag_len);
            }
        }
        log_event("PK11_Encrypt", "enc", *info,
                  iv.empty() ? nullptr : iv.data(), iv.size(),
                  tag_ptr, tag_len);
    }

    (void)maxOut;
    return status;
}

typedef SECStatus (*fn_PK11_Decrypt)(PK11SymKey*, CK_MECHANISM_TYPE, SECItem*,
                                     unsigned char*, unsigned int*, unsigned int,
                                     const unsigned char*, unsigned int);
static fn_PK11_Decrypt real_PK11_Decrypt = nullptr;

SECStatus PK11_Decrypt(PK11SymKey* symKey,
                      CK_MECHANISM_TYPE mechanism,
                      SECItem* param,
                      unsigned char* out,
                      unsigned int* outLen,
                      unsigned int maxOut,
                      const unsigned char* in,
                      unsigned int inLen) {
    RESOLVE_SYM(real_PK11_Decrypt, "PK11_Decrypt");
    if (!real_PK11_Decrypt) {
        return SECFailure;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_Decrypt(symKey, mechanism, param, out, outLen, maxOut, in, inLen);
    }

    std::vector<unsigned char> iv;
    auto info = fetch_symkey(symKey);
    if (info.has_value()) {
        std::vector<unsigned char> unused_tag;
        extract_iv_and_tag(info->mechanism, param, iv, unused_tag);
    }

    SECStatus status = real_PK11_Decrypt(symKey, mechanism, param, out, outLen, maxOut, in, inLen);

    if (info.has_value()) {
        // For GCM, assume input ends with tag of length recorded previously.
        const unsigned char* tag_ptr = nullptr;
        size_t tag_len = 0;
        if (info->mechanism == CKM_AES_GCM && param && param->data) {
            const CK_GCM_PARAMS* gcm = reinterpret_cast<const CK_GCM_PARAMS*>(param->data);
            if (gcm->ulTagBits >= 8) {
                tag_len = std::min(static_cast<size_t>(gcm->ulTagBits / 8), kMaxSnapshot);
                if (tag_len > 0 && inLen >= tag_len) {
                    tag_ptr = in + (inLen - tag_len);
                }
            }
        }
        log_event("PK11_Decrypt", "dec", *info,
                  iv.empty() ? nullptr : iv.data(), iv.size(),
                  tag_ptr, tag_len);
    }

    (void)maxOut;
    return status;
}

} // extern "C"
