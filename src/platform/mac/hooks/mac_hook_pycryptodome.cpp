// src/platform/mac/hooks/mac_hook_pycryptodome.cpp
// Mirrors the Linux PyCryptodome hook for macOS using DYLD interposing.

#include "common/pch.h"
#include "common/output.h"
#include "common/reentry_guard.h"
#include "platform/mac/resolver.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace {

constexpr const char* SURFACE = "pycryptodome";
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

static void* resolve_pycryptodome_symbol(const char* name) {
    if (!name || !*name) return nullptr;
    if (void* sym = resolve_next_symbol(name)) {
        return sym;
    }

    // Fall back to scanning already-loaded images (Python extension modules).
    uint32_t image_count = _dyld_image_count();
    for (uint32_t idx = 0; idx < image_count; ++idx) {
        const char* image_name = _dyld_get_image_name(idx);
        if (!image_name) {
            continue;
        }
        // Skip our own image to prevent recursion.
        if (std::strstr(image_name, "libhook.dylib")) {
            continue;
        }
        void* handle = dlopen(image_name, RTLD_NOLOAD | RTLD_LAZY);
        if (!handle) {
            continue;
        }
        void* sym = dlsym(handle, name);
        if (sym) {
            if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
                std::fprintf(stderr, "[hook_macos] pycryptodome resolved '%s' via %s\n",
                             name, image_name);
            }
            return sym;
        }
    }
    if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
        std::fprintf(stderr, "[hook_macos] pycryptodome symbol '%s' unresolved\n", name);
    }
    return nullptr;
}

#define RESOLVE_SYM(var, name_literal)                                               \
    do {                                                                             \
        if (!(var)) {                                                                \
            (var) = reinterpret_cast<decltype(var)>(resolve_pycryptodome_symbol(name_literal)); \
        }                                                                            \
    } while (0)

std::vector<uint8_t> snapshot_buffer(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return {};
    }
    size_t copy_len = std::min(len, kMaxSnapshot);
    std::vector<uint8_t> out(copy_len);
    std::memcpy(out.data(), data, copy_len);
    return out;
}

struct AesState {
    std::vector<uint8_t> key;
};

struct CtrState {
    std::vector<uint8_t> counter_block;
    std::vector<uint8_t> key;
    bool is_tag_cipher = false;
};

std::mutex g_aes_mu;
std::unordered_map<const void*, AesState> g_aes_states;

std::mutex g_ctr_mu;
std::unordered_map<const void*, CtrState> g_ctr_states;

void log_key_event(const char* api,
                   const char* direction,
                   const char* cipher_name,
                   const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& iv,
                   const std::vector<uint8_t>& tag) {
    ndjson_log_key_event(
        SURFACE,
        api,
        direction,
        cipher_name,
        key.empty() ? nullptr : key.data(),
        static_cast<int>(key.size()),
        iv.empty() ? nullptr : iv.data(),
        static_cast<int>(iv.size()),
        tag.empty() ? nullptr : tag.data(),
        static_cast<int>(tag.size()));
}

} // namespace

extern "C" {

int AES_start_operation(const uint8_t*, size_t, void**) __attribute__((weak_import));
int AES_stop_operation(void*) __attribute__((weak_import));
int AESNI_start_operation(const uint8_t*, size_t, void**) __attribute__((weak_import));
int AESNI_stop_operation(void*) __attribute__((weak_import));
int CTR_start_operation(void*, uint8_t*, size_t, size_t, unsigned, unsigned, void**) __attribute__((weak_import));
int CTR_encrypt(void*, const uint8_t*, uint8_t*, size_t) __attribute__((weak_import));
int CTR_stop_operation(void*) __attribute__((weak_import));

using fn_AES_start_operation = int (*)(const uint8_t*, size_t, void**);
static fn_AES_start_operation real_AES_start_operation = nullptr;

int hook_AES_start_operation(const uint8_t* key,
                             size_t key_len,
                             void** pResult) {
    RESOLVE_SYM(real_AES_start_operation, "AES_start_operation");
    if (!real_AES_start_operation) return -1;

    ReentryGuard guard;
    if (!guard) {
        return real_AES_start_operation(key, key_len, pResult);
    }

    int ret = real_AES_start_operation(key, key_len, pResult);
    if (ret == 0 && pResult && *pResult) {
        auto copy = snapshot_buffer(key, key_len);
        if (!copy.empty()) {
            const void* state = *pResult;
            {
                std::lock_guard<std::mutex> lock(g_aes_mu);
                g_aes_states[state] = {copy};
            }
            log_key_event("AES_start_operation", "set_key", "AES", copy, {}, {});
        }
    }
    return ret;
}
DYLD_INTERPOSE(hook_AES_start_operation, AES_start_operation)

using fn_AES_stop_operation = int (*)(void*);
static fn_AES_stop_operation real_AES_stop_operation = nullptr;

int hook_AES_stop_operation(void* state) {
    RESOLVE_SYM(real_AES_stop_operation, "AES_stop_operation");
    if (!real_AES_stop_operation) return -1;

    {
        std::lock_guard<std::mutex> lock(g_aes_mu);
        g_aes_states.erase(state);
    }
    return real_AES_stop_operation(state);
}
DYLD_INTERPOSE(hook_AES_stop_operation, AES_stop_operation)

using fn_AESNI_start_operation = int (*)(const uint8_t*, size_t, void**);
static fn_AESNI_start_operation real_AESNI_start_operation = nullptr;

int hook_AESNI_start_operation(const uint8_t* key,
                               size_t key_len,
                               void** pResult) {
    RESOLVE_SYM(real_AESNI_start_operation, "AESNI_start_operation");
    if (!real_AESNI_start_operation) {
        // AESNI path absent; fall back to software cipher
        return AES_start_operation(key, key_len, pResult);
    }

    ReentryGuard guard;
    if (!guard) {
        return real_AESNI_start_operation(key, key_len, pResult);
    }

    int ret = real_AESNI_start_operation(key, key_len, pResult);
    if (ret == 0 && pResult && *pResult) {
        auto copy = snapshot_buffer(key, key_len);
        if (!copy.empty()) {
            const void* state = *pResult;
            {
                std::lock_guard<std::mutex> lock(g_aes_mu);
                g_aes_states[state] = {copy};
            }
            log_key_event("AESNI_start_operation", "set_key", "AES", copy, {}, {});
        }
    }
    return ret;
}
DYLD_INTERPOSE(hook_AESNI_start_operation, AESNI_start_operation)

using fn_AESNI_stop_operation = int (*)(void*);
static fn_AESNI_stop_operation real_AESNI_stop_operation = nullptr;

int hook_AESNI_stop_operation(void* state) {
    RESOLVE_SYM(real_AESNI_stop_operation, "AESNI_stop_operation");
    if (!real_AESNI_stop_operation) {
        return AES_stop_operation(state);
    }

    {
        std::lock_guard<std::mutex> lock(g_aes_mu);
        g_aes_states.erase(state);
    }
    return real_AESNI_stop_operation(state);
}
DYLD_INTERPOSE(hook_AESNI_stop_operation, AESNI_stop_operation)

using fn_CTR_start_operation = int (*)(void*, uint8_t*, size_t, size_t, unsigned, unsigned, void**);
static fn_CTR_start_operation real_CTR_start_operation = nullptr;

int hook_CTR_start_operation(void* cipher,
                             uint8_t* initialCounterBlock,
                             size_t initialCounterBlock_len,
                             size_t prefix_len,
                             unsigned counter_len,
                             unsigned littleEndian,
                             void** pResult) {
    RESOLVE_SYM(real_CTR_start_operation, "CTR_start_operation");
    if (!real_CTR_start_operation) return -1;

    ReentryGuard guard;
    if (!guard) {
        return real_CTR_start_operation(cipher,
                                        initialCounterBlock,
                                        initialCounterBlock_len,
                                        prefix_len,
                                        counter_len,
                                        littleEndian,
                                        pResult);
    }

    int ret = real_CTR_start_operation(cipher,
                                       initialCounterBlock,
                                       initialCounterBlock_len,
                                       prefix_len,
                                       counter_len,
                                       littleEndian,
                                       pResult);
    if (ret == 0 && pResult && *pResult && initialCounterBlock && initialCounterBlock_len > 0) {
        auto iv_copy = snapshot_buffer(initialCounterBlock, initialCounterBlock_len);
        std::vector<uint8_t> key_copy;
        {
            std::lock_guard<std::mutex> lock(g_aes_mu);
            auto it = g_aes_states.find(cipher);
            if (it != g_aes_states.end()) {
                key_copy = it->second.key;
            }
        }
        CtrState state;
        state.counter_block = std::move(iv_copy);
        state.key = std::move(key_copy);
        state.is_tag_cipher = (prefix_len == 0 && counter_len == initialCounterBlock_len);

        {
            std::lock_guard<std::mutex> lock(g_ctr_mu);
            g_ctr_states[*pResult] = state;
        }
        log_key_event("CTR_start_operation",
                      "set_iv",
                      "AES-CTR",
                      g_ctr_states[*pResult].key,
                      g_ctr_states[*pResult].counter_block,
                      {});
    }
    return ret;
}
DYLD_INTERPOSE(hook_CTR_start_operation, CTR_start_operation)

using fn_CTR_encrypt = int (*)(void*, const uint8_t*, uint8_t*, size_t);
static fn_CTR_encrypt real_CTR_encrypt = nullptr;

int hook_CTR_encrypt(void* state,
                     const uint8_t* in,
                     uint8_t* out,
                     size_t data_len) {
    RESOLVE_SYM(real_CTR_encrypt, "CTR_encrypt");
    if (!real_CTR_encrypt) return -1;

    ReentryGuard guard;
    if (!guard) {
        return real_CTR_encrypt(state, in, out, data_len);
    }

    CtrState ctr_state;
    bool have_state = false;
    {
        std::lock_guard<std::mutex> lock(g_ctr_mu);
        auto it = g_ctr_states.find(state);
        if (it != g_ctr_states.end()) {
            ctr_state = it->second;
            have_state = true;
        }
    }

    int ret = real_CTR_encrypt(state, in, out, data_len);
    if (ret == 0 && have_state && ctr_state.is_tag_cipher && out && data_len > 0) {
        auto tag_copy = snapshot_buffer(out, data_len);
        log_key_event("CTR_encrypt",
                      "tag",
                      "AES-GCM",
                      ctr_state.key,
                      ctr_state.counter_block,
                      tag_copy);
    }
    return ret;
}
DYLD_INTERPOSE(hook_CTR_encrypt, CTR_encrypt)

using fn_CTR_stop_operation = int (*)(void*);
static fn_CTR_stop_operation real_CTR_stop_operation = nullptr;

int hook_CTR_stop_operation(void* state) {
    RESOLVE_SYM(real_CTR_stop_operation, "CTR_stop_operation");
    if (!real_CTR_stop_operation) return -1;

    {
        std::lock_guard<std::mutex> lock(g_ctr_mu);
        g_ctr_states.erase(state);
    }
    return real_CTR_stop_operation(state);
}
DYLD_INTERPOSE(hook_CTR_stop_operation, CTR_stop_operation)

} // extern "C"
