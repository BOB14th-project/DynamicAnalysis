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
    log_key_and_len("EVP_EncryptInit_ex", "enc", ctx, type, key);
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
    log_key_and_len("EVP_CipherInit_ex", enc ? "enc" : "dec", ctx, type, key);
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
    log_key_and_len("EVP_DecryptInit_ex", "dec", ctx, type, key);
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
    log_key_and_len("EVP_EncryptInit_ex2", "enc", ctx, type, key);
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
    log_key_and_len("EVP_DecryptInit_ex2", "dec", ctx, type, key);
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
    log_key_and_len("EVP_CipherInit_ex2", enc ? "enc" : "dec", ctx, type, key);
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

// HMAC 함수 훅
#include <openssl/hmac.h>
using hmac_fn = unsigned char*(*)(const EVP_MD*, const void*, int, const unsigned char*, size_t, unsigned char*, unsigned int*);
static hmac_fn real_HMAC = nullptr;

extern "C" unsigned char* HMAC(const EVP_MD* evp_md, const void* key, int key_len,
                               const unsigned char* d, size_t n, unsigned char* md, unsigned int* md_len) {
    if (!real_HMAC) {
        real_HMAC = (hmac_fn)resolve_next_symbol("HMAC");
        if (!real_HMAC) return nullptr;
    }
    
    // HMAC 키 로깅
    if (key && key_len > 0) {
        const char* md_name = EVP_MD_name ? EVP_MD_name(evp_md) : "unknown";
        log_crypto_event("HMAC", "mac", md_name, (const unsigned char*)key, key_len);
    }
    
    return real_HMAC(evp_md, key, key_len, d, n, md, md_len);
}

// PBKDF2 함수 훅
using pbkdf2_fn = int(*)(const char*, int, const unsigned char*, int, int, const EVP_MD*, int, unsigned char*);
static pbkdf2_fn real_PKCS5_PBKDF2_HMAC = nullptr;

extern "C" int PKCS5_PBKDF2_HMAC(const char* pass, int passlen, const unsigned char* salt,
                                  int saltlen, int iter, const EVP_MD* digest,
                                  int keylen, unsigned char* out) {
    if (!real_PKCS5_PBKDF2_HMAC) {
        real_PKCS5_PBKDF2_HMAC = (pbkdf2_fn)resolve_next_symbol("PKCS5_PBKDF2_HMAC");
        if (!real_PKCS5_PBKDF2_HMAC) return 0;
    }
    
    // PBKDF2 패스워드와 솔트 로깅
    if (pass && passlen > 0) {
        log_crypto_event("PBKDF2", "derive", "password", (const unsigned char*)pass, passlen);
    }
    if (salt && saltlen > 0) {
        log_crypto_event("PBKDF2", "derive", "salt", salt, saltlen);
    }
    
    return real_PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out);
}

// EVP Digest Sign 함수들 (RSA 서명 등)
using digest_sign_init_fn = int(*)(EVP_MD_CTX*, EVP_PKEY_CTX**, const EVP_MD*, ENGINE*, EVP_PKEY*);
static digest_sign_init_fn real_EVP_DigestSignInit = nullptr;

extern "C" int EVP_DigestSignInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const EVP_MD* type,
                                  ENGINE* e, EVP_PKEY* pkey) {
    if (!real_EVP_DigestSignInit) {
        real_EVP_DigestSignInit = (digest_sign_init_fn)resolve_next_symbol("EVP_DigestSignInit");
        if (!real_EVP_DigestSignInit) return 0;
    }
    
    // RSA/EC 서명 키 로깅
    if (pkey) {
        const char* key_type = "unknown";
        int key_id = EVP_PKEY_id(pkey);
        if (key_id == EVP_PKEY_RSA) key_type = "RSA";
        else if (key_id == EVP_PKEY_EC) key_type = "EC";
        
        log_crypto_event("EVP_DigestSignInit", "sign", key_type, nullptr, 0);
    }
    
    return real_EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

// EVP PKEY derive (ECDH 등)
using pkey_derive_fn = int(*)(EVP_PKEY_CTX*, unsigned char*, size_t*);
static pkey_derive_fn real_EVP_PKEY_derive = nullptr;

extern "C" int EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen) {
    if (!real_EVP_PKEY_derive) {
        real_EVP_PKEY_derive = (pkey_derive_fn)resolve_next_symbol("EVP_PKEY_derive");
        if (!real_EVP_PKEY_derive) return 0;
    }
    
    int ret = real_EVP_PKEY_derive(ctx, key, keylen);
    
    // 키 파생 후 결과 로깅 (성공 시에만)
    if (ret == 1 && key && keylen && *keylen > 0) {
        log_crypto_event("EVP_PKEY_derive", "derive", "ECDH", key, *keylen);
    }
    
    return ret;
}
