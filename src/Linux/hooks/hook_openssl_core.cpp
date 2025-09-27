// src/hooks/hook_openssl_core.cpp
#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"

#include <openssl/evp.h>

typedef struct engine_st ENGINE;

#define RESOLVE_SYM(var, name) do{ if(!(var)) (var)=(decltype(var))resolve_next_symbol(name);}while(0)
static constexpr const char* SURFACE = "openssl";

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

// ---- real_* pointers ----
using fn_EVP_EncryptInit_ex = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);
static fn_EVP_EncryptInit_ex real_EVP_EncryptInit_ex = nullptr;

using fn_EVP_DecryptInit_ex = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);
static fn_EVP_DecryptInit_ex real_EVP_DecryptInit_ex = nullptr;

using fn_EVP_CipherInit_ex  = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*, int);
static fn_EVP_CipherInit_ex real_EVP_CipherInit_ex = nullptr;

using fn_EVP_CIPHER_CTX_set_key_length = int(*)(EVP_CIPHER_CTX*, int);
static fn_EVP_CIPHER_CTX_set_key_length real_EVP_CIPHER_CTX_set_key_length = nullptr;

using fn_EVP_CIPHER_CTX_ctrl = int(*)(EVP_CIPHER_CTX*, int, int, void*);
static fn_EVP_CIPHER_CTX_ctrl real_EVP_CIPHER_CTX_ctrl = nullptr;

// ---- 공통 로깅 헬퍼 (type==NULL일 때 ctx에서 복구) ----
static inline void log_init_ex(const char* api, const char* dir,
                               EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                               const unsigned char* key, const unsigned char* iv)
{
  const EVP_CIPHER* c = type ? type : cipher_from_ctx(ctx);
  const char* cname = cipher_name(c);
  int klen = (key && c) ? EVP_CIPHER_key_length(c) : 0;
  int ivlen= (iv  && c) ? EVP_CIPHER_iv_length(c)  : 0;

  ndjson_log_key_event(
      SURFACE, api, dir, cname,
      key, klen,
      iv, ivlen,
      /*tag*/nullptr, 0);
}


/*** hook_* bodies and exported symbols ***/
extern "C" int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                  ENGINE* eng, const unsigned char* key, const unsigned char* iv)
{
  RESOLVE_SYM(real_EVP_EncryptInit_ex, "EVP_EncryptInit_ex");
  if (!real_EVP_EncryptInit_ex) return 0;
  ReentryGuard g; if (!g) return real_EVP_EncryptInit_ex(ctx, type, eng, key, iv);

  log_init_ex("EVP_EncryptInit_ex", "enc", ctx, type, key, iv);
  return real_EVP_EncryptInit_ex(ctx, type, eng, key, iv);
}

extern "C" int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                  ENGINE* eng, const unsigned char* key, const unsigned char* iv)
{
  RESOLVE_SYM(real_EVP_DecryptInit_ex, "EVP_DecryptInit_ex");
  if (!real_EVP_DecryptInit_ex) return 0;
  ReentryGuard g; if (!g) return real_EVP_DecryptInit_ex(ctx, type, eng, key, iv);
  log_init_ex("EVP_DecryptInit_ex", "dec", ctx, type, key, iv);
  return real_EVP_DecryptInit_ex(ctx, type, eng, key, iv);
}


extern "C" int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                                 ENGINE* eng, const unsigned char* key, const unsigned char* iv, int enc)
{
  RESOLVE_SYM(real_EVP_CipherInit_ex, "EVP_CipherInit_ex");
  if (!real_EVP_CipherInit_ex) return 0;
  ReentryGuard g; if (!g) return real_EVP_CipherInit_ex(ctx, type, eng, key, iv, enc);
  log_init_ex("EVP_CipherInit_ex", enc ? "enc" : "dec", ctx, type, key, iv);
  return real_EVP_CipherInit_ex(ctx, type, eng, key, iv, enc);
}

extern "C" int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX* ctx, int keylen)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_set_key_length, "EVP_CIPHER_CTX_set_key_length");
  if (!real_EVP_CIPHER_CTX_set_key_length) return 0;
  ReentryGuard g; if (!g) return real_EVP_CIPHER_CTX_set_key_length(ctx, keylen);
  ndjson_log_key_event(
      SURFACE, "EVP_CIPHER_CTX_set_key_length", "set_keylen",
      /*cipher*/cipher_name(cipher_from_ctx(ctx)),
      /*key*/nullptr, keylen,
      /*iv*/nullptr, 0,
      /*tag*/nullptr, 0);
  return real_EVP_CIPHER_CTX_set_key_length(ctx, keylen);
}

// ---- GCM/AEAD 메타 로깅: IVLEN/TAG ----
extern "C" int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_ctrl, "EVP_CIPHER_CTX_ctrl");
  if (!real_EVP_CIPHER_CTX_ctrl) return 0;

  ReentryGuard g; if (!g) return real_EVP_CIPHER_CTX_ctrl(ctx, cmd, p1, p2);

  int r = real_EVP_CIPHER_CTX_ctrl(ctx, cmd, p1, p2);

  const EVP_CIPHER* c = cipher_from_ctx(ctx);
  const char* cname = cipher_name(c);

  switch (cmd) {
    case EVP_CTRL_GCM_SET_IVLEN:
      ndjson_log_key_event(SURFACE, "EVP_CIPHER_CTX_ctrl", "set_ivlen",
                           cname, nullptr, 0, nullptr, p1, nullptr, 0);
      break;
    case EVP_CTRL_AEAD_SET_TAG:
      if (p2 && p1 > 0) {
        ndjson_log_key_event(SURFACE, "EVP_CIPHER_CTX_ctrl", "set_tag",
                             cname, nullptr, 0, nullptr, 0,
                             (const unsigned char*)p2, p1);
      }
      break;
    case EVP_CTRL_AEAD_GET_TAG:
      if (p2 && p1 > 0) {
        ndjson_log_key_event(SURFACE, "EVP_CIPHER_CTX_ctrl", "get_tag",
                             cname, nullptr, 0, nullptr, 0,
                             (const unsigned char*)p2, p1);
      }
      break;
    default:
      break;
  }
  return r;
}
