// src/platform/mac/hooks/mac_hook_nss.cpp
// Intercepts Mozilla NSS PK11 APIs on macOS to expose symmetric key usage.

#include "common/pch.h"
#include "common/output.h"
#include "common/reentry_guard.h"
#include "platform/mac/resolver.h"

#if !__has_include(<nss/nss.h>) || !__has_include(<nss/pk11pub.h>)
#error "mac_hook_nss.cpp requires NSS headers"
#endif

#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nspr/prio.h>

#include <dlfcn.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

static constexpr const char* SURFACE = "nss";
constexpr size_t kMaxSnapshot = 512;

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) \
    static const struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };
#endif

static void* resolve_nss_symbol(const char* name) {
    if (!name || !*name) return nullptr;
    if (void* sym = resolve_next_symbol(name)) {
        return sym;
    }

    static const char* kCandidates[] = {
        "libnss3.dylib",
        "/opt/homebrew/lib/libnss3.dylib",
        "/usr/local/lib/libnss3.dylib",
        nullptr
    };

    void* sym = nullptr;
    for (const char* candidate : kCandidates) {
        if (!candidate) break;
        void* handle = dlopen(candidate, RTLD_NOLOAD | RTLD_LAZY);
        if (!handle) {
            handle = dlopen(candidate, RTLD_LAZY | RTLD_LOCAL);
        }
        if (!handle) continue;
        sym = dlsym(handle, name);
        if (sym) {
            break;
        }
    }

    if (!sym) {
        if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
            std::fprintf(stderr, "[hook_macos] nss symbol '%s' unresolved\n", name);
        }
    }
    return sym;
}

#define RESOLVE_SYM(var, name_literal)                                               \
    do {                                                                             \
        if (!(var)) {                                                                \
            (var) = reinterpret_cast<decltype(var)>(resolve_nss_symbol(name_literal)); \
        }                                                                            \
    } while (0)

namespace {

struct SymKeyInfo {
    CK_MECHANISM_TYPE mechanism = CKM_INVALID_MECHANISM;
    std::vector<unsigned char> key_bytes;
};

std::mutex g_symkey_mu;
std::unordered_map<PK11SymKey*, SymKeyInfo> g_symkey_map;

std::string mechanism_to_string(CK_MECHANISM_TYPE mech) {
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

std::vector<unsigned char> copy_buffer(const void* data, size_t len) {
    if (!data || len == 0) return {};
    size_t copy_len = std::min(len, kMaxSnapshot);
    const auto* bytes = static_cast<const unsigned char*>(data);
    return std::vector<unsigned char>(bytes, bytes + static_cast<std::ptrdiff_t>(copy_len));
}

void remember_symkey(PK11SymKey* key,
                     CK_MECHANISM_TYPE mech,
                     const SECItem* key_item) {
    if (!key) return;
    SymKeyInfo info;
    info.mechanism = mech;
    if (key_item && key_item->data && key_item->len > 0) {
        info.key_bytes = copy_buffer(key_item->data, static_cast<size_t>(key_item->len));
    }
    std::lock_guard<std::mutex> lock(g_symkey_mu);
    g_symkey_map[key] = std::move(info);
}

std::optional<SymKeyInfo> fetch_symkey(PK11SymKey* key) {
    std::lock_guard<std::mutex> lock(g_symkey_mu);
    auto it = g_symkey_map.find(key);
    if (it == g_symkey_map.end()) return std::nullopt;
    return it->second;
}

void forget_symkey(PK11SymKey* key) {
    std::lock_guard<std::mutex> lock(g_symkey_mu);
    g_symkey_map.erase(key);
}

void log_event(const char* api,
               const char* direction,
               const SymKeyInfo& info,
               const unsigned char* iv,
               size_t iv_len,
               const unsigned char* tag,
               size_t tag_len) {
    auto cipher_name = mechanism_to_string(info.mechanism);
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

void extract_iv_and_tag(CK_MECHANISM_TYPE mech,
                        const SECItem* param,
                        std::vector<unsigned char>& iv_out,
                        std::vector<unsigned char>& tag_out) {
    iv_out.clear();
    tag_out.clear();
    if (!param || !param->data || param->len == 0) return;

    if (mech == CKM_AES_GCM && param->len >= sizeof(CK_GCM_PARAMS)) {
        const auto* gcm = reinterpret_cast<const CK_GCM_PARAMS*>(param->data);
        iv_out = copy_buffer(gcm->pIv, gcm->ulIvLen);
        if (gcm->ulTagBits >= 8) {
            size_t tag_len = std::min(static_cast<size_t>(gcm->ulTagBits / 8), kMaxSnapshot);
            tag_out.resize(tag_len, 0);
        }
        return;
    }

    if ((mech == CKM_AES_CBC || mech == CKM_AES_CBC_PAD) && param->len > 0) {
        iv_out = copy_buffer(param->data, static_cast<size_t>(param->len));
        return;
    }
}

} // namespace

extern "C" {

SECStatus PK11_EncryptWithSymKey(PK11SymKey*, CK_MECHANISM_TYPE,
                                 SECItem*, unsigned char*, unsigned int*,
                                 unsigned int, const unsigned char*, unsigned int) __attribute__((weak_import));
SECStatus PK11_DecryptWithSymKey(PK11SymKey*, CK_MECHANISM_TYPE,
                                 SECItem*, unsigned char*, unsigned int*,
                                 unsigned int, const unsigned char*, unsigned int) __attribute__((weak_import));

PK11SymKey* PK11_ImportSymKey(PK11SlotInfo*, CK_MECHANISM_TYPE,
                              PK11Origin, CK_ATTRIBUTE_TYPE, SECItem*, void*) __attribute__((weak_import));
void PK11_FreeSymKey(PK11SymKey*) __attribute__((weak_import));
SECStatus PK11_Encrypt(PK11SymKey*, CK_MECHANISM_TYPE, SECItem*, unsigned char*,
                       unsigned int*, unsigned int, const unsigned char*, unsigned int) __attribute__((weak_import));
SECStatus PK11_Decrypt(PK11SymKey*, CK_MECHANISM_TYPE, SECItem*, unsigned char*,
                       unsigned int*, unsigned int, const unsigned char*, unsigned int) __attribute__((weak_import));

using fn_PK11_ImportSymKey = PK11SymKey* (*)(PK11SlotInfo*, CK_MECHANISM_TYPE,
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
    if (!real_PK11_ImportSymKey) return nullptr;

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_ImportSymKey(slot, mechanism, origin, operation, key, wincx);
    }

    if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
        std::fprintf(stderr, "[hook_macos][nss] PK11_ImportSymKey mech=0x%lx\n",
                     static_cast<unsigned long>(mechanism));
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

using fn_PK11_FreeSymKey = void (*)(PK11SymKey*);
static fn_PK11_FreeSymKey real_PK11_FreeSymKey = nullptr;

void PK11_FreeSymKey(PK11SymKey* symKey) {
    RESOLVE_SYM(real_PK11_FreeSymKey, "PK11_FreeSymKey");
    if (!real_PK11_FreeSymKey) return;

    forget_symkey(symKey);

    ReentryGuard guard;
    if (!guard) {
        real_PK11_FreeSymKey(symKey);
        return;
    }
    real_PK11_FreeSymKey(symKey);
}

using fn_PK11_Encrypt = SECStatus (*)(PK11SymKey*, CK_MECHANISM_TYPE,
                                      SECItem*, unsigned char*, unsigned int*,
                                      unsigned int, const unsigned char*, unsigned int);
static fn_PK11_Encrypt real_PK11_Encrypt = nullptr;

SECStatus PK11_Encrypt(PK11SymKey* symKey,
                       CK_MECHANISM_TYPE mechanism,
                       SECItem* param,
                       unsigned char* out,
                       unsigned int* outLen,
                       unsigned int maxLen,
                       const unsigned char* in,
                       unsigned int inLen) {
    RESOLVE_SYM(real_PK11_Encrypt, "PK11_Encrypt");
    if (!real_PK11_Encrypt) return SECFailure;

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_Encrypt(symKey, mechanism, param, out, outLen,
                                 maxLen, in, inLen);
    }

    SECStatus status = real_PK11_Encrypt(symKey, mechanism, param,
                                         out, outLen, maxLen, in, inLen);
    if (status == SECSuccess) {
        if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
            std::fprintf(stderr, "[hook_macos][nss] PK11_Encrypt success bytes=%u\n",
                         outLen ? *outLen : 0u);
        }
        if (auto info = fetch_symkey(symKey)) {
            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            extract_iv_and_tag(mechanism, param, iv, tag);
            log_event("PK11_Encrypt", "enc", *info,
                      iv.empty() ? nullptr : iv.data(), iv.size(),
                      tag.empty() ? nullptr : tag.data(), tag.size());
        }
    }
    return status;
}

using fn_PK11_Decrypt = SECStatus (*)(PK11SymKey*, CK_MECHANISM_TYPE,
                                      SECItem*, unsigned char*, unsigned int*,
                                      unsigned int, const unsigned char*, unsigned int);
static fn_PK11_Decrypt real_PK11_Decrypt = nullptr;

SECStatus PK11_Decrypt(PK11SymKey* symKey,
                       CK_MECHANISM_TYPE mechanism,
                       SECItem* param,
                       unsigned char* out,
                       unsigned int* outLen,
                       unsigned int maxLen,
                       const unsigned char* in,
                       unsigned int inLen) {
    RESOLVE_SYM(real_PK11_Decrypt, "PK11_Decrypt");
    if (!real_PK11_Decrypt) return SECFailure;

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_Decrypt(symKey, mechanism, param, out, outLen,
                                 maxLen, in, inLen);
    }

    SECStatus status = real_PK11_Decrypt(symKey, mechanism, param,
                                         out, outLen, maxLen, in, inLen);
    if (status == SECSuccess) {
        if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
            std::fprintf(stderr, "[hook_macos][nss] PK11_Decrypt success bytes=%u\n",
                         outLen ? *outLen : 0u);
        }
        if (auto info = fetch_symkey(symKey)) {
            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            extract_iv_and_tag(mechanism, param, iv, tag);
            log_event("PK11_Decrypt", "dec", *info,
                      iv.empty() ? nullptr : iv.data(), iv.size(),
                      tag.empty() ? nullptr : tag.data(), tag.size());
        }
    }
    return status;
}

using fn_PK11_EncryptWithSymKey = SECStatus (*)(PK11SymKey*, CK_MECHANISM_TYPE,
                                                SECItem*, unsigned char*, unsigned int*,
                                                unsigned int, const unsigned char*, unsigned int);
static fn_PK11_EncryptWithSymKey real_PK11_EncryptWithSymKey = nullptr;

SECStatus PK11_EncryptWithSymKey(PK11SymKey* symKey,
                                 CK_MECHANISM_TYPE mechanism,
                                 SECItem* param,
                                 unsigned char* out,
                                 unsigned int* outLen,
                                 unsigned int maxLen,
                                 const unsigned char* in,
                                 unsigned int inLen) {
    RESOLVE_SYM(real_PK11_EncryptWithSymKey, "PK11_EncryptWithSymKey");
    if (!real_PK11_EncryptWithSymKey) return SECFailure;

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_EncryptWithSymKey(symKey, mechanism, param,
                                           out, outLen, maxLen, in, inLen);
    }

    SECStatus status = real_PK11_EncryptWithSymKey(symKey, mechanism, param,
                                                   out, outLen, maxLen, in, inLen);
    if (status == SECSuccess) {
        if (auto info = fetch_symkey(symKey)) {
            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            extract_iv_and_tag(mechanism, param, iv, tag);
            log_event("PK11_EncryptWithSymKey", "enc", *info,
                      iv.empty() ? nullptr : iv.data(), iv.size(),
                      tag.empty() ? nullptr : tag.data(), tag.size());
        }
    }
    return status;
}

using fn_PK11_DecryptWithSymKey = SECStatus (*)(PK11SymKey*, CK_MECHANISM_TYPE,
                                                SECItem*, unsigned char*, unsigned int*,
                                                unsigned int, const unsigned char*, unsigned int);
static fn_PK11_DecryptWithSymKey real_PK11_DecryptWithSymKey = nullptr;

SECStatus PK11_DecryptWithSymKey(PK11SymKey* symKey,
                                 CK_MECHANISM_TYPE mechanism,
                                 SECItem* param,
                                 unsigned char* out,
                                 unsigned int* outLen,
                                 unsigned int maxLen,
                                 const unsigned char* in,
                                 unsigned int inLen) {
    RESOLVE_SYM(real_PK11_DecryptWithSymKey, "PK11_DecryptWithSymKey");
    if (!real_PK11_DecryptWithSymKey) return SECFailure;

    ReentryGuard guard;
    if (!guard) {
        return real_PK11_DecryptWithSymKey(symKey, mechanism, param,
                                           out, outLen, maxLen, in, inLen);
    }

    SECStatus status = real_PK11_DecryptWithSymKey(symKey, mechanism, param,
                                                   out, outLen, maxLen, in, inLen);
    if (status == SECSuccess) {
        if (auto info = fetch_symkey(symKey)) {
            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            extract_iv_and_tag(mechanism, param, iv, tag);
            log_event("PK11_DecryptWithSymKey", "dec", *info,
                      iv.empty() ? nullptr : iv.data(), iv.size(),
                      tag.empty() ? nullptr : tag.data(), tag.size());
        }
    }
    return status;
}

} // extern "C"
