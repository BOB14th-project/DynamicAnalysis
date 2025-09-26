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

using evp_cipher_init_ex = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                                  const unsigned char*, const unsigned char*, int);
static evp_cipher_init_ex real_EVP_CipherInit_ex = nullptr;

extern "C" int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl,
                                 const unsigned char* key, const unsigned char* iv, int enc) {
    if (!real_EVP_CipherInit_ex) {
        real_EVP_CipherInit_ex = (evp_cipher_init_ex)resolve_next_symbol("EVP_CipherInit_ex");
        if (!real_EVP_CipherInit_ex) return 0;
    }
    log_key_and_len(ctx, type, key);
    return real_EVP_CipherInit_ex(ctx, type, impl, key, iv, enc);
}

using evp_decrypt_init_ex = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                                   const unsigned char*, const unsigned char*);
static evp_decrypt_init_ex real_EVP_DecryptInit_ex = nullptr;

extern "C" int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                  ENGINE* impl, const unsigned char* key, const unsigned char* iv) {
    if (!real_EVP_DecryptInit_ex) {
        real_EVP_DecryptInit_ex = (evp_decrypt_init_ex)resolve_next_symbol("EVP_DecryptInit_ex");
        if (!real_EVP_DecryptInit_ex) return 0;
    }
    log_key_and_len(ctx, type, key);
    return real_EVP_DecryptInit_ex(ctx, type, impl, key, iv);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>

using evp_encrypt_init_ex2 = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                                    const unsigned char* /*key*/, const unsigned char* /*iv*/,
                                    const OSSL_PARAM* /*params*/);
static evp_encrypt_init_ex2 real_EVP_EncryptInit_ex2 = nullptr;

extern "C" int EVP_EncryptInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                   const unsigned char* key, const unsigned char* iv,
                                   const OSSL_PARAM* params) {
    if (!real_EVP_EncryptInit_ex2) {
        real_EVP_EncryptInit_ex2 = (evp_encrypt_init_ex2)resolve_next_symbol("EVP_EncryptInit_ex2");
        if (!real_EVP_EncryptInit_ex2) return 0;
    }
    // key/iv 인자로도 오고, params로도 올 수 있음 → 둘 다 로깅
    log_key_and_len(ctx, type, key);
    //log_key_iv_from_params(params);
    return real_EVP_EncryptInit_ex2(ctx, type, key, iv, params);
}

using evp_decrypt_init_ex2 = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                                    const unsigned char*, const unsigned char*,
                                    const OSSL_PARAM*);
static evp_decrypt_init_ex2 real_EVP_DecryptInit_ex2 = nullptr;

extern "C" int EVP_DecryptInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                   const unsigned char* key, const unsigned char* iv,
                                   const OSSL_PARAM* params) {
    if (!real_EVP_DecryptInit_ex2) {
        real_EVP_DecryptInit_ex2 = (evp_decrypt_init_ex2)resolve_next_symbol("EVP_DecryptInit_ex2");
        if (!real_EVP_DecryptInit_ex2) return 0;
    }
    log_key_and_len(ctx, type, key);
    //log_key_iv_from_params(params);
    return real_EVP_DecryptInit_ex2(ctx, type, key, iv, params);
}

using evp_cipher_init_ex2 = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                                   const unsigned char*, const unsigned char*,
                                   int /*enc*/, const OSSL_PARAM*);
static evp_cipher_init_ex2 real_EVP_CipherInit_ex2 = nullptr;

extern "C" int EVP_CipherInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                  const unsigned char* key, const unsigned char* iv,
                                  int enc, const OSSL_PARAM* params) {
    if (!real_EVP_CipherInit_ex2) {
        real_EVP_CipherInit_ex2 = (evp_cipher_init_ex2)resolve_next_symbol("EVP_CipherInit_ex2");
        if (!real_EVP_CipherInit_ex2) return 0;
    }
    log_key_and_len(ctx, type, key);
    //log_key_iv_from_params(params);
    return real_EVP_CipherInit_ex2(ctx, type, key, iv, enc, params);
}
#endif


using set_keylen_fn = int(*)(EVP_CIPHER_CTX*, int);
static set_keylen_fn real_EVP_CIPHER_CTX_set_key_length = nullptr;

extern "C" int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX* ctx, int keylen) {
    if (!real_EVP_CIPHER_CTX_set_key_length) {
        real_EVP_CIPHER_CTX_set_key_length =
            (set_keylen_fn)resolve_next_symbol("EVP_CIPHER_CTX_set_key_length");
        if (!real_EVP_CIPHER_CTX_set_key_length) return 0;
    }
    char buf[64];
    int n = std::snprintf(buf, sizeof(buf), "[HOOK] keylen set: %d bytes (%d bits)\n", keylen, keylen*8);
    (void)!write(2, buf, (size_t)n);
    return real_EVP_CIPHER_CTX_set_key_length(ctx, keylen);
}
