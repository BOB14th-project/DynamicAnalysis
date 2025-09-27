// src/hooks/hook_openssl_provider.cpp
#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <cstring>

#define RESOLVE_SYM(var, name) do { if(!(var)) (var) = (decltype(var))resolve_next_symbol(name); } while(0)
static constexpr const char* SURFACE = "openssl";

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

// ---- 유틸: cipher 이름/CTX에서 cipher 복구 ----
static inline const char* cipher_name(const EVP_CIPHER* c) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  extern const char* EVP_CIPHER_get0_name(const EVP_CIPHER*);
  return c ? EVP_CIPHER_get0_name(c) : nullptr;
#else
  return c ? OBJ_nid2sn(EVP_CIPHER_nid(c)) : nullptr;
#endif
}

static inline const EVP_CIPHER* cipher_from_ctx(const EVP_CIPHER_CTX* ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  extern const EVP_CIPHER* EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX*);
  return ctx ? EVP_CIPHER_CTX_get0_cipher(ctx) : nullptr;
#else
  return ctx ? EVP_CIPHER_CTX_cipher(ctx) : nullptr;
#endif
}

// ---- real_* pointers (OpenSSL 3 ex2 정식 시그니처) ----
using fn_EncryptInit_ex2 = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                                  const unsigned char*, const unsigned char*,
                                  const OSSL_PARAM*);
using fn_DecryptInit_ex2 = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                                  const unsigned char*, const unsigned char*,
                                  const OSSL_PARAM*);
using fn_CipherInit_ex2  = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                                  const unsigned char*, const unsigned char*,
                                  int, const OSSL_PARAM*);

static fn_EncryptInit_ex2 real_EVP_EncryptInit_ex2 = nullptr;
static fn_DecryptInit_ex2 real_EVP_DecryptInit_ex2 = nullptr;
static fn_CipherInit_ex2  real_EVP_CipherInit_ex2  = nullptr;

using fn_setp = int(*)(EVP_CIPHER_CTX*, const OSSL_PARAM*);
using fn_getp = int(*)(EVP_CIPHER_CTX*, OSSL_PARAM*);
static fn_setp real_EVP_CIPHER_CTX_set_params = nullptr;
static fn_getp real_EVP_CIPHER_CTX_get_params = nullptr;

// ---- params 로깅 ----
static inline void log_params_as_keyevent(const char* api,
                                          const EVP_CIPHER* type,
                                          const OSSL_PARAM* p) {
  if (!p) return;

  const char* cname = cipher_name(type);
  size_t keylen = 0;
  const void* ivp = nullptr;   size_t ivsz  = 0;
  const void* tagp = nullptr;  size_t tagsz = 0;

  for (const OSSL_PARAM* q = p; q && q->key; ++q) {
    const char* k = q->key; if (!k) break;

    if      (!std::strcmp(k, OSSL_CIPHER_PARAM_KEYLEN))            OSSL_PARAM_get_size_t(q, &keylen);
    else if (!std::strcmp(k, OSSL_CIPHER_PARAM_IV))                OSSL_PARAM_get_octet_string_ptr(q, &ivp, &ivsz);
    else if (!std::strcmp(k, OSSL_CIPHER_PARAM_AEAD_TAG))          OSSL_PARAM_get_octet_string_ptr(q, &tagp, &tagsz);
    else if (!std::strcmp(k, OSSL_CIPHER_PARAM_IVLEN))             OSSL_PARAM_get_size_t(q, &ivsz);
    else if (!std::strcmp(k, OSSL_CIPHER_PARAM_AEAD_TAGLEN))       OSSL_PARAM_get_size_t(q, &tagsz);
  }

  ndjson_log_key_event(
    SURFACE, api, "params", cname,
    /*key*/nullptr, (int)keylen,
    (const unsigned char*)ivp, (int)ivsz,
    (const unsigned char*)tagp, (int)tagsz
  );
}

// ---- ex2 호출에서 넘어온 key/iv도 즉시 로깅 ----
static inline void log_key_iv_from_ex2(const char* api,
                                       EVP_CIPHER_CTX* ctx,
                                       const EVP_CIPHER* type,
                                       const unsigned char* key,
                                       const unsigned char* iv,
                                       const char* dir_hint /*"enc"/"dec"/"encdec"*/)
{
  const EVP_CIPHER* c = type ? type : cipher_from_ctx(ctx);
  const char* cname = cipher_name(c);
  int klen = (key && c) ? EVP_CIPHER_key_length(c) : 0;
  int ivlen= (iv  && c) ? EVP_CIPHER_iv_length(c)  : 0;

  if (key || iv) {
    ndjson_log_key_event(SURFACE, api, dir_hint, cname,
                         key, klen, iv, ivlen, nullptr, 0);
  }
}

/*** exported (ex2) ***/
extern "C" int EVP_EncryptInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                   const unsigned char* key, const unsigned char* iv,
                                   const OSSL_PARAM* params)
{
  RESOLVE_SYM(real_EVP_EncryptInit_ex2, "EVP_EncryptInit_ex2");
  if (!real_EVP_EncryptInit_ex2) return 0;

  ReentryGuard g; if (!g) return real_EVP_EncryptInit_ex2(ctx, type, key, iv, params);

  log_params_as_keyevent("EVP_EncryptInit_ex2", type, params);
  log_key_iv_from_ex2("EVP_EncryptInit_ex2", ctx, type, key, iv, "enc"); // 방향 힌트
  return real_EVP_EncryptInit_ex2(ctx, type, key, iv, params);
}

extern "C" int EVP_DecryptInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                   const unsigned char* key, const unsigned char* iv,
                                   const OSSL_PARAM* params)
{
  RESOLVE_SYM(real_EVP_DecryptInit_ex2, "EVP_DecryptInit_ex2");
  if (!real_EVP_DecryptInit_ex2) return 0;

  ReentryGuard g; if (!g) return real_EVP_DecryptInit_ex2(ctx, type, key, iv, params);

  log_params_as_keyevent("EVP_DecryptInit_ex2", type, params);
  log_key_iv_from_ex2("EVP_DecryptInit_ex2", ctx, type, key, iv, "dec");
  return real_EVP_DecryptInit_ex2(ctx, type, key, iv, params);
}

extern "C" int EVP_CipherInit_ex2(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                  const unsigned char* key, const unsigned char* iv,
                                  int enc, const OSSL_PARAM* params)
{
  RESOLVE_SYM(real_EVP_CipherInit_ex2, "EVP_CipherInit_ex2");
  if (!real_EVP_CipherInit_ex2) return 0;

  ReentryGuard g; if (!g) return real_EVP_CipherInit_ex2(ctx, type, key, iv, enc, params);

  log_params_as_keyevent("EVP_CipherInit_ex2", type, params);
  log_key_iv_from_ex2(enc ? "EVP_CipherInit_ex2.enc" : "EVP_CipherInit_ex2.dec",
                      ctx, type, key, iv, enc ? "enc":"dec");
  return real_EVP_CipherInit_ex2(ctx, type, key, iv, enc, params);
}

extern "C" int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX* ctx, const OSSL_PARAM* params)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_set_params, "EVP_CIPHER_CTX_set_params");
  if (!real_EVP_CIPHER_CTX_set_params) return 0;

  ReentryGuard g; if (!g) return real_EVP_CIPHER_CTX_set_params(ctx, params);
  log_params_as_keyevent("EVP_CIPHER_CTX_set_params", /*type*/cipher_from_ctx(ctx), params);
  return real_EVP_CIPHER_CTX_set_params(ctx, params);
}

extern "C" int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX* ctx, OSSL_PARAM* params)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_get_params, "EVP_CIPHER_CTX_get_params");
  if (!real_EVP_CIPHER_CTX_get_params) return 0;

  ReentryGuard g; if (!g) return real_EVP_CIPHER_CTX_get_params(ctx, params);
  log_params_as_keyevent("EVP_CIPHER_CTX_get_params", /*type*/cipher_from_ctx(ctx), params);
  return real_EVP_CIPHER_CTX_get_params(ctx, params);
}

#endif // OPENSSL_VERSION_NUMBER >= 0x30000000L
