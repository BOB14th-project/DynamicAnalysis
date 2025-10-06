// crypto_utils.cpp - Windows version
#include "common/pch.h"
#include "common/crypto_utils.h"
#include "common/output.h"

#include <openssl/evp.h>
#include <io.h>

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

#define STDERR_FD 2

// key dump
void dump_hex_stderr(const unsigned char* p, int n) {
    if (!p || n <= 0) return;
    char buf[3]; // 2 hex + NUL
    for (int i = 0; i < n; ++i) {
        int m = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%02x", p[i]);
        (void)_write(STDERR_FD, buf, m);
    }
    (void)_write(STDERR_FD, "\n", 1);
}

static inline const EVP_CIPHER* pick_cipher(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return type ? type : (ctx ? EVP_CIPHER_CTX_get0_cipher(ctx) : nullptr);
#else
    return type ? type : (ctx ? EVP_CIPHER_CTX_cipher(ctx) : nullptr);
#endif
}

static inline const char* cipher_name(const EVP_CIPHER* c) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return c ? EVP_CIPHER_get0_name(c) : nullptr;
#else
    return c ? EVP_CIPHER_name(c) : nullptr;
#endif
}

namespace {

static const char* surface_for_openssl() {
    return "openssl";
}

static const char* stderr_prefix() {
    return "[HOOK]";
}

} // namespace

void log_key_and_len(const char* api,
                     const char* direction,
                     EVP_CIPHER_CTX* ctx,
                     const EVP_CIPHER* type,
                     const unsigned char* key)
{
    const EVP_CIPHER* c = pick_cipher(ctx, type);
    const char* cname = cipher_name(c);
    const int klen = get_effective_keylen(ctx, type);

    const char* surface = surface_for_openssl();
    const char* prefix = stderr_prefix();

    // 사람이 보는 stderr
    if (key && klen > 0) {
        char buf[128];
        int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                              "%s %s%s%s keylen: %d bits\n",
                              prefix,
                              api ? api : "", direction ? " " : "",
                              direction ? direction : "", klen * 8);
        (void)_write(STDERR_FD, buf, n);
        char key_header[64];
        int kh = _snprintf_s(key_header, sizeof(key_header), _TRUNCATE, "%s key: ", prefix);
        (void)_write(STDERR_FD, key_header, kh);
        dump_hex_stderr(key, klen);
    }

    // NDJSON (키 바이트를 그대로 기록)
    ndjson_log_key_event(surface, api, direction, cname,
                         key, klen,
                         /*iv*/nullptr, 0,
                         /*tag*/nullptr, 0);
}

// 일반적인 암호화 이벤트 로깅 함수 (HMAC, PBKDF2, RSA, ECDH 등)
void log_crypto_event(const char* api, const char* direction, const char* algorithm,
                      const unsigned char* key_data, int key_len) {
    const char* surface = surface_for_openssl();
    const char* prefix = stderr_prefix();

    // 사람이 보는 stderr 로깅
    if (key_data && key_len > 0) {
        char buf[256];
        int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                              "%s %s %s %s keylen: %d bytes (%d bits)\n",
                              prefix,
                              api ? api : "", direction ? direction : "",
                              algorithm ? algorithm : "", key_len, key_len * 8);
        (void)_write(STDERR_FD, buf, n);
        char key_header[64];
        int kh = _snprintf_s(key_header, sizeof(key_header), _TRUNCATE, "%s key: ", prefix);
        (void)_write(STDERR_FD, key_header, kh);
        dump_hex_stderr(key_data, key_len);
    } else {
        char buf[256];
        int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                              "%s %s %s %s\n",
                              prefix,
                              api ? api : "", direction ? direction : "",
                              algorithm ? algorithm : "");
        (void)_write(STDERR_FD, buf, n);
    }

    // NDJSON 로깅
    ndjson_log_key_event(surface, api, direction, algorithm, key_data, key_len,
                         /*iv*/nullptr, 0, /*tag*/nullptr, 0);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/core_names.h>

void log_key_iv_from_params(const OSSL_PARAM* params) {
    if (!params) return;
    const char* prefix = stderr_prefix();

    // IV
    if (const OSSL_PARAM* piv = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IV)) {
        if (piv->data && piv->data_size > 0) {
            char head[64];
            int n = _snprintf_s(head, sizeof(head), _TRUNCATE, "%s key (params): ", prefix);
            (void)_write(STDERR_FD, head, n);
            dump_hex_stderr(reinterpret_cast<const unsigned char*>(piv->data), (int)piv->data_size);
        }
    }

    // IV 길이 (있으면 정보용)
    if (const OSSL_PARAM* pl = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)) {
        size_t ivlen = 0;
        if (OSSL_PARAM_get_size_t(pl, &ivlen)) {
            char line[64];
            int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                                  "%s ivlen (params): %zu bytes\n", prefix, ivlen);
            (void)_write(STDERR_FD, line, n);
        }
    }

    // AEAD 태그(복호 시 제공될 수 있음)
    if (const OSSL_PARAM* ptag = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG)) {
        if (ptag->data && ptag->data_size > 0) {
            char head[64];
            int n = _snprintf_s(head, sizeof(head), _TRUNCATE, "%s aead tag (params): ", prefix);
            (void)_write(STDERR_FD, head, n);
            dump_hex_stderr(reinterpret_cast<const unsigned char*>(ptag->data),
                            static_cast<int>(ptag->data_size));
        }
    }

    // (참고) 키 길이는 KEYLEN으로 올 수 있지만 키 바이트는 params에 오지 않음
    if (const OSSL_PARAM* pklen = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN)) {
        size_t klen = 0;
        if (OSSL_PARAM_get_size_t(pklen, &klen)) {
            char line[64];
            int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                                  "%s keylen (params): %zu bytes (%zu bits)\n",
                                  prefix, klen, klen * 8);
            (void)_write(STDERR_FD, line, n);
        }
    }
}
#endif
