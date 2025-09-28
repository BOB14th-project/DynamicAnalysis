// src/Linux/hooks/hook_pycryptodome.cpp
// Intercepts PyCryptodome AES primitives (AES_start_operation, CTR_start_operation)
// to capture key/nonce/tag material when Python code uses Crypto.Cipher.AES.

#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"
#include "log.h"

#include <dlfcn.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace {

constexpr const char* SURFACE = "pycryptodome";
constexpr size_t kMaxSnapshot = 512;

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
    size_t prefix_len = 0;
    unsigned counter_len = 0;
    bool little_endian = false;
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

#define RESOLVE_SYM(var, literal)                                                      \
    do {                                                                               \
        if (!(var)) {                                                                  \
            (var) = reinterpret_cast<decltype(var)>(resolve_next_symbol(literal));     \
        }                                                                              \
    } while (0)

} // namespace

extern "C" {

using fn_AES_start_operation = int (*)(const uint8_t*, size_t, void**);
static fn_AES_start_operation real_AES_start_operation = nullptr;
static bool tried_aes_start = false;

int AES_start_operation(const uint8_t* key,
                        size_t key_len,
                        void** pResult) {
    if (!real_AES_start_operation && !tried_aes_start) {
        tried_aes_start = true;
        real_AES_start_operation = reinterpret_cast<fn_AES_start_operation>(
            resolve_next_symbol("AES_start_operation"));
    }
    if (!real_AES_start_operation) {
        return -1;
    }

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
            log_key_event("AES_start_operation",
                          "set_key",
                          "AES",
                          copy,
                          {},
                          {});
        }
    }
    return ret;
}

using fn_AES_stop_operation = int (*)(void*);
static fn_AES_stop_operation real_AES_stop_operation = nullptr;

int AES_stop_operation(void* state) {
    RESOLVE_SYM(real_AES_stop_operation, "AES_stop_operation");
    if (!real_AES_stop_operation) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_AES_stop_operation(state);
    }

    {
        std::lock_guard<std::mutex> lock(g_aes_mu);
        g_aes_states.erase(state);
    }
    return real_AES_stop_operation(state);
}

using fn_AESNI_start_operation = int (*)(const uint8_t*, size_t, void**);
static fn_AESNI_start_operation real_AESNI_start_operation = nullptr;
static bool tried_aesni_start = false;

int AESNI_start_operation(const uint8_t* key,
                          size_t key_len,
                          void** pResult) {
    if (!real_AESNI_start_operation && !tried_aesni_start) {
        tried_aesni_start = true;
        real_AESNI_start_operation = reinterpret_cast<fn_AESNI_start_operation>(
            resolve_next_symbol("AESNI_start_operation"));
    }
    if (!real_AESNI_start_operation) {
        return -1;
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
            log_key_event("AESNI_start_operation",
                          "set_key",
                          "AES",
                          copy,
                          {},
                          {});
        }
    }
    return ret;
}

using fn_AESNI_stop_operation = int (*)(void*);
static fn_AESNI_stop_operation real_AESNI_stop_operation = nullptr;
static bool tried_aesni_stop = false;

int AESNI_stop_operation(void* state) {
    if (!real_AESNI_stop_operation && !tried_aesni_stop) {
        tried_aesni_stop = true;
        real_AESNI_stop_operation = reinterpret_cast<fn_AESNI_stop_operation>(
            resolve_next_symbol("AESNI_stop_operation"));
    }
    if (!real_AESNI_stop_operation) {
        return 0;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_AESNI_stop_operation(state);
    }

    {
        std::lock_guard<std::mutex> lock(g_aes_mu);
        g_aes_states.erase(state);
    }
    return real_AESNI_stop_operation(state);
}

using fn_CTR_start_operation = int (*)(void*, uint8_t*, size_t, size_t, unsigned, unsigned, void**);
static fn_CTR_start_operation real_CTR_start_operation = nullptr;
static bool tried_ctr_start = false;

int CTR_start_operation(void* cipher,
                        uint8_t* initialCounterBlock,
                        size_t initialCounterBlock_len,
                        size_t prefix_len,
                        unsigned counter_len,
                        unsigned littleEndian,
                        void** pResult) {
    if (!real_CTR_start_operation && !tried_ctr_start) {
        tried_ctr_start = true;
        real_CTR_start_operation = reinterpret_cast<fn_CTR_start_operation>(
            resolve_next_symbol("CTR_start_operation"));
    }
    if (!real_CTR_start_operation) {
        return -1;
    }

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
       std::vector<uint8_t> key;
       {
           std::lock_guard<std::mutex> lock(g_aes_mu);
           auto it = g_aes_states.find(cipher);
           if (it != g_aes_states.end()) {
               key = it->second.key;
           }
       }
       const void* ctr_state = *pResult;
       CtrState state;
       state.counter_block = std::move(iv_copy);
       state.prefix_len = prefix_len;
       state.counter_len = counter_len;
       state.little_endian = littleEndian != 0;
       state.key = key;
       state.is_tag_cipher = (prefix_len == 0 && counter_len == initialCounterBlock_len);
       {
           std::lock_guard<std::mutex> lock(g_ctr_mu);
           g_ctr_states[ctr_state] = state;
       }
        log_key_event("CTR_start_operation",
                      "set_iv",
                      "AES-CTR",
                      key,
                      state.counter_block,
                      {});
   }
    return ret;
}

using fn_CTR_encrypt = int (*)(void*, const uint8_t*, uint8_t*, size_t);
static fn_CTR_encrypt real_CTR_encrypt = nullptr;
static bool tried_ctr_encrypt = false;

int CTR_encrypt(void* state,
                const uint8_t* in,
                uint8_t* out,
                size_t data_len) {
    if (!real_CTR_encrypt && !tried_ctr_encrypt) {
        tried_ctr_encrypt = true;
        real_CTR_encrypt = reinterpret_cast<fn_CTR_encrypt>(
            resolve_next_symbol("CTR_encrypt"));
    }
    if (!real_CTR_encrypt) {
        return -1;
    }

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

using fn_CTR_stop_operation = int (*)(void*);
static fn_CTR_stop_operation real_CTR_stop_operation = nullptr;
static bool tried_ctr_stop = false;

int CTR_stop_operation(void* state) {
    if (!real_CTR_stop_operation && !tried_ctr_stop) {
        tried_ctr_stop = true;
        real_CTR_stop_operation = reinterpret_cast<fn_CTR_stop_operation>(
            resolve_next_symbol("CTR_stop_operation"));
    }
    if (!real_CTR_stop_operation) {
        return -1;
    }

    ReentryGuard guard;
    if (!guard) {
        return real_CTR_stop_operation(state);
    }

    {
        std::lock_guard<std::mutex> lock(g_ctr_mu);
        g_ctr_states.erase(state);
    }
    return real_CTR_stop_operation(state);
}

using fn_dlsym = void* (*)(void*, const char*);
static fn_dlsym real_dlsym_ptr = nullptr;

static fn_dlsym get_real_dlsym() {
    if (!real_dlsym_ptr) {
#ifdef __GLIBC__
        real_dlsym_ptr = reinterpret_cast<fn_dlsym>(dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5"));
        if (!real_dlsym_ptr) {
            void* libdl = dlopen("libdl.so.2", RTLD_LAZY | RTLD_LOCAL);
            if (libdl) {
                real_dlsym_ptr = reinterpret_cast<fn_dlsym>(dlvsym(libdl, "dlsym", "GLIBC_2.2.5"));
                if (!real_dlsym_ptr) {
                    real_dlsym_ptr = reinterpret_cast<fn_dlsym>(dlvsym(libdl, "dlsym", "GLIBC_2.3"));
                }
            }
        }
#else
        real_dlsym_ptr = reinterpret_cast<fn_dlsym>(dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5"));
#endif
    }
    return real_dlsym_ptr;
}

void* dlsym(void* handle, const char* symbol) {
    fn_dlsym real = get_real_dlsym();
    void* addr = real ? real(handle, symbol) : nullptr;

    if (handle == RTLD_NEXT || handle == RTLD_DEFAULT) {
        return addr;
    }

    if (addr) {
        if (strcmp(symbol, "AES_start_operation") == 0) {
            real_AES_start_operation = reinterpret_cast<fn_AES_start_operation>(addr);
            return reinterpret_cast<void*>(&AES_start_operation);
        }
        if (strcmp(symbol, "AES_stop_operation") == 0) {
            real_AES_stop_operation = reinterpret_cast<fn_AES_stop_operation>(addr);
            return reinterpret_cast<void*>(&AES_stop_operation);
        }
        if (strcmp(symbol, "AESNI_start_operation") == 0) {
            real_AESNI_start_operation = reinterpret_cast<fn_AESNI_start_operation>(addr);
            return reinterpret_cast<void*>(&AESNI_start_operation);
        }
        if (strcmp(symbol, "AESNI_stop_operation") == 0) {
            real_AESNI_stop_operation = reinterpret_cast<fn_AESNI_stop_operation>(addr);
            return reinterpret_cast<void*>(&AESNI_stop_operation);
        }
        if (strcmp(symbol, "CTR_start_operation") == 0) {
            real_CTR_start_operation = reinterpret_cast<fn_CTR_start_operation>(addr);
            return reinterpret_cast<void*>(&CTR_start_operation);
        }
        if (strcmp(symbol, "CTR_encrypt") == 0) {
            real_CTR_encrypt = reinterpret_cast<fn_CTR_encrypt>(addr);
            return reinterpret_cast<void*>(&CTR_encrypt);
        }
        if (strcmp(symbol, "CTR_stop_operation") == 0) {
            real_CTR_stop_operation = reinterpret_cast<fn_CTR_stop_operation>(addr);
            return reinterpret_cast<void*>(&CTR_stop_operation);
        }
    }

    return addr;
}

} // extern "C"
