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
        int len = snprintf(klen_str, sizeof(klen_str), "[HOOK] keylen: %d bits\n",klen*8);
        (void)!write(STDERR_FILENO, klen_str, len);
        (void)!write(STDERR_FILENO, "[HOOK] key: ",12);
        dump_hex_stderr(key, klen);
    }
}