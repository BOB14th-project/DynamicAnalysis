// openssl_hooks.cpp
#include "pch.h"
#include "hook_common.h"
#include "log.h"
#include "resolver.h"
#include "crypto_utils.h"
#include <openssl/evp.h>

typedef struct engine_st ENGINE;

// use function pointer
using evp_init_ex = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                           const unsigned char*, const unsigned char*);
static evp_init_ex real_EVP_EncryptInit_ex = nullptr;

// hook function
extern "C" int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx,
                                  const EVP_CIPHER* type,
                                  ENGINE* impl,
                                  const unsigned char* key,
                                  const unsigned char* iv) {
    if (!real_EVP_EncryptInit_ex) {
        real_EVP_EncryptInit_ex = (evp_init_ex)resolve_next_symbol("EVP_EncryptInit_ex");
        if (!real_EVP_EncryptInit_ex) return 0;
    }

    log_key_and_len(ctx, type, key);

    return real_EVP_EncryptInit_ex(ctx, type, impl, key, iv);
}
