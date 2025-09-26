// get_key.cpp
#include "pch.h"
#include "crypto_utils.h"

// OpenSSL/LibreSSL 버전별 안전한 키 길이 얻기
int get_effective_keylen(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type) {
#if defined(LIBRESSL_VERSION_NUMBER)
    // LibreSSL은 1.1.x 계열과 유사 API
    int l = EVP_CIPHER_CTX_key_length(ctx);
    if (l > 0) return l;
    const EVP_CIPHER* c = type ? type : EVP_CIPHER_CTX_cipher(ctx);
    return c ? EVP_CIPHER_key_length(c) : 0;
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x
    int l = EVP_CIPHER_CTX_get_key_length(ctx);
    if (l > 0) return l;
    const EVP_CIPHER* c = type ? type : EVP_CIPHER_CTX_get0_cipher(ctx);
    return c ? EVP_CIPHER_get_key_length(c) : 0;
#else
    // OpenSSL 1.1.0/1.1.1
    int l = EVP_CIPHER_CTX_key_length(ctx);
    if (l > 0) return l;
    const EVP_CIPHER* c = type ? type : EVP_CIPHER_CTX_cipher(ctx);
    return c ? EVP_CIPHER_key_length(c) : 0;
#endif
}

// key dump
void dump_hex_stderr(const unsigned char* p, int n) {
    if (!p || n <= 0) return;
    char buf[3]; // 2 hex + NUL
    for (int i = 0; i < n; ++i) {
        int m = std::snprintf(buf, sizeof(buf), "%02x", p[i]);
        (void)!write(STDERR_FILENO, buf, (size_t)m);
    }
    (void)!write(STDERR_FILENO, "\n", 1);
}


void log_key_and_len(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, const unsigned char* key){
    if (!ctx && !type) return; // 둘 다 없다면 스킵
    int klen = get_effective_keylen(ctx,type);
    if (key && klen > 0){
        char klen_str[64];
        int len = std::snprintf(klen_str, sizeof(klen_str), "[HOOK] keylen: %d bits\n",klen*8);
        (void)!write(STDERR_FILENO, klen_str, len);
        (void)!write(STDERR_FILENO, "[HOOK] key: ",12);
        dump_hex_stderr(key, klen);
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/core_names.h>

void log_key_iv_from_params(const OSSL_PARAM* params){
    if(!params) return;
    // IV
    if(const OSSL_PARAM* piv = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IV)) {
        if (piv->data && piv->data_size > 0){
            (void)!write(2, "[HOOK] key (params): ",22);
            dump_hex_stderr(reinterpret_cast<const unsigned char*>(piv->data), (int)piv->data_size);
        }
    }
    // IV 길이 (있으면 정보용)
    if (const OSSL_PARAM* pl = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)) {
        size_t ivlen = 0;
        if (OSSL_PARAM_get_size_t(pl, &ivlen)) {
            char line[64];
            int n = std::snprintf(line, sizeof(line),
                                  "[HOOK] ivlen (params): %zu bytes\n", ivlen);
            (void)!write(2, line, (size_t)n);
        }
    }

    // AEAD 태그(복호 시 제공될 수 있음)
    if (const OSSL_PARAM* ptag = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG)) {
        if (ptag->data && ptag->data_size > 0) {
            (void)!write(2, "[HOOK] aead tag (params): ", 26);
            dump_hex_stderr(reinterpret_cast<const unsigned char*>(ptag->data),
                            static_cast<int>(ptag->data_size));
        }
    }

    // (참고) 키 길이는 KEYLEN으로 올 수 있지만 키 바이트는 params에 오지 않음
    if (const OSSL_PARAM* pklen = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN)) {
        size_t klen = 0;
        if (OSSL_PARAM_get_size_t(pklen, &klen)) {
            char line[64];
            int n = std::snprintf(line, sizeof(line),
                                  "[HOOK] keylen (params): %zu bytes (%zu bits)\n",
                                  klen, klen * 8);
            (void)!write(2, line, (size_t)n);
        }
    }
}
#endif