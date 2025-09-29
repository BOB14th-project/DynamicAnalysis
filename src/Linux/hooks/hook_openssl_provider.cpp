// src/hooks/hook_openssl_provider.cpp
#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"
#include "hook_openssl_state.h"

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
static inline void log_params_and_update(const char* api,
                                         EVP_CIPHER_CTX* ctx,
                                         const EVP_CIPHER* type,
                                         const OSSL_PARAM* params) {
  if (!params) return;

  const EVP_CIPHER* cipher = type ? type : cipher_from_ctx(ctx);
  const char* cname = cipher_name(cipher);

  size_t keylen_hint = 0;
  size_t ivlen_hint = 0;
  size_t taglen_hint = 0;
  std::vector<unsigned char> iv_vec;
  std::vector<unsigned char> tag_vec;

  for (const OSSL_PARAM* q = params; q && q->key; ++q) {
    const char* k = q->key;
    if (!k) break;

    if (!std::strcmp(k, OSSL_CIPHER_PARAM_KEYLEN)) {
      OSSL_PARAM_get_size_t(q, &keylen_hint);
    } else if (!std::strcmp(k, OSSL_CIPHER_PARAM_IV)) {
      const void* ptr = nullptr;
      size_t sz = 0;
      if (OSSL_PARAM_get_octet_string_ptr(q, &ptr, &sz) && ptr && sz > 0) {
        iv_vec.assign(static_cast<const unsigned char*>(ptr),
                      static_cast<const unsigned char*>(ptr) + sz);
      }
    } else if (!std::strcmp(k, OSSL_CIPHER_PARAM_IVLEN)) {
      OSSL_PARAM_get_size_t(q, &ivlen_hint);
    } else if (!std::strcmp(k, OSSL_CIPHER_PARAM_AEAD_TAG)) {
      const void* ptr = nullptr;
      size_t sz = 0;
      if (OSSL_PARAM_get_octet_string_ptr(q, &ptr, &sz) && ptr && sz > 0) {
        tag_vec.assign(static_cast<const unsigned char*>(ptr),
                       static_cast<const unsigned char*>(ptr) + sz);
      }
    } else if (!std::strcmp(k, OSSL_CIPHER_PARAM_AEAD_TAGLEN)) {
      OSSL_PARAM_get_size_t(q, &taglen_hint);
    }
  }

  if (ctx && cname && !iv_vec.empty()) {
    openssl_state_remember_iv(ctx, cname, iv_vec.data(), iv_vec.size());
  }

  std::string dir = "params";
  if (keylen_hint) dir += "[keylen=" + std::to_string(keylen_hint) + "]";
  if (ivlen_hint) dir += "[ivlen=" + std::to_string(ivlen_hint) + "]";
  if (taglen_hint) dir += "[taglen=" + std::to_string(taglen_hint) + "]";

  ndjson_log_key_event(SURFACE,
                       api,
                       dir.c_str(),
                       cname,
                       nullptr,
                       0,
                       iv_vec.empty() ? nullptr : iv_vec.data(),
                       static_cast<int>(iv_vec.size()),
                       tag_vec.empty() ? nullptr : tag_vec.data(),
                       static_cast<int>(tag_vec.size()));
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

  log_params_and_update("EVP_EncryptInit_ex2", ctx, type, params);
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

  log_params_and_update("EVP_DecryptInit_ex2", ctx, type, params);
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

  log_params_and_update("EVP_CipherInit_ex2", ctx, type, params);
  log_key_iv_from_ex2(enc ? "EVP_CipherInit_ex2.enc" : "EVP_CipherInit_ex2.dec",
                      ctx, type, key, iv, enc ? "enc":"dec");
  return real_EVP_CipherInit_ex2(ctx, type, key, iv, enc, params);
}

extern "C" int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX* ctx, const OSSL_PARAM* params)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_set_params, "EVP_CIPHER_CTX_set_params");
  if (!real_EVP_CIPHER_CTX_set_params) return 0;

  ReentryGuard g; if (!g) return real_EVP_CIPHER_CTX_set_params(ctx, params);
  log_params_and_update("EVP_CIPHER_CTX_set_params", ctx, cipher_from_ctx(ctx), params);
  return real_EVP_CIPHER_CTX_set_params(ctx, params);
}

extern "C" int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX* ctx, OSSL_PARAM* params)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_get_params, "EVP_CIPHER_CTX_get_params");
  if (!real_EVP_CIPHER_CTX_get_params) return 0;

  ReentryGuard g; if (!g) return real_EVP_CIPHER_CTX_get_params(ctx, params);
  log_params_and_update("EVP_CIPHER_CTX_get_params", ctx, cipher_from_ctx(ctx), params);
  return real_EVP_CIPHER_CTX_get_params(ctx, params);
}

#endif // OPENSSL_VERSION_NUMBER >= 0x30000000L
