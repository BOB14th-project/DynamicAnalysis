// src/hooks/hook_openssl_core.cpp
#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"
#include "hook_openssl_state.h"

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

  if (cname) {
    openssl_state_remember(ctx,
                           cname,
                           (key && klen > 0) ? key : nullptr,
                           (key && klen > 0) ? static_cast<size_t>(klen) : 0,
                           (iv && ivlen > 0) ? iv : nullptr,
                           (iv && ivlen > 0) ? static_cast<size_t>(ivlen) : 0);
  }

  ndjson_log_key_event(
      SURFACE, api, dir, cname,
      key, klen,
      iv, ivlen,
      /*tag*/nullptr, 0);
}

static inline void log_update_event(const char* api,
                                    EVP_CIPHER_CTX* ctx,
                                    const char* dir_prefix,
                                    size_t length)
{
  OpenSSLState st;
  const EVP_CIPHER* cipher = cipher_from_ctx(ctx);
  const char* fallback = cipher ? cipher_name(cipher) : nullptr;
  if (!openssl_state_lookup(ctx, st)) {
    if (!fallback) return;
    char dir[64];
    snprintf(dir, sizeof(dir), "%s[len=%zu]", dir_prefix, length);
    ndjson_log_key_event(SURFACE, api, dir, fallback,
                         nullptr, 0, nullptr, 0, nullptr, 0);
    return;
  }
  const char* cname = st.cipher_name.empty() ? fallback : st.cipher_name.c_str();
  char dir[64];
  snprintf(dir, sizeof(dir), "%s[len=%zu]", dir_prefix, length);
  ndjson_log_key_event(
      SURFACE,
      api,
      dir,
      cname,
      st.key.empty() ? nullptr : st.key.data(),
      static_cast<int>(st.key.size()),
      st.iv.empty() ? nullptr : st.iv.data(),
      static_cast<int>(st.iv.size()),
      nullptr,
      0);
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
#ifdef EVP_CTRL_GCM_SET_IV_FIXED
    case EVP_CTRL_GCM_SET_IV_FIXED:
      if (p2 && p1 > 0) {
        openssl_state_remember_iv(ctx, cname,
                                  reinterpret_cast<const unsigned char*>(p2),
                                  static_cast<size_t>(p1));
        ndjson_log_key_event(SURFACE, "EVP_CIPHER_CTX_ctrl", "set_iv",
                             cname,
                             nullptr, 0,
                             reinterpret_cast<const unsigned char*>(p2), p1,
                             nullptr, 0);
      }
      break;
#endif
#ifdef EVP_CTRL_AEAD_SET_IV
    case EVP_CTRL_AEAD_SET_IV:
      if (p2 && p1 > 0) {
        openssl_state_remember_iv(ctx, cname,
                                  reinterpret_cast<const unsigned char*>(p2),
                                  static_cast<size_t>(p1));
        ndjson_log_key_event(SURFACE, "EVP_CIPHER_CTX_ctrl", "set_iv",
                             cname,
                             nullptr, 0,
                             reinterpret_cast<const unsigned char*>(p2), p1,
                             nullptr, 0);
      }
      break;
#endif
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

// ---- EVP Update/Final 함수들 ----
using fn_EVP_EncryptUpdate = int(*)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);
static fn_EVP_EncryptUpdate real_EVP_EncryptUpdate = nullptr;

using fn_EVP_EncryptFinal_ex = int(*)(EVP_CIPHER_CTX*, unsigned char*, int*);
static fn_EVP_EncryptFinal_ex real_EVP_EncryptFinal_ex = nullptr;

using fn_EVP_DecryptUpdate = int(*)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);
static fn_EVP_DecryptUpdate real_EVP_DecryptUpdate = nullptr;

using fn_EVP_DecryptFinal_ex = int(*)(EVP_CIPHER_CTX*, unsigned char*, int*);
static fn_EVP_DecryptFinal_ex real_EVP_DecryptFinal_ex = nullptr;

using fn_EVP_CipherUpdate = int(*)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);
static fn_EVP_CipherUpdate real_EVP_CipherUpdate = nullptr;

using fn_EVP_CipherFinal_ex = int(*)(EVP_CIPHER_CTX*, unsigned char*, int*);
static fn_EVP_CipherFinal_ex real_EVP_CipherFinal_ex = nullptr;

using fn_EVP_CIPHER_CTX_reset = int(*)(EVP_CIPHER_CTX*);
static fn_EVP_CIPHER_CTX_reset real_EVP_CIPHER_CTX_reset = nullptr;

using fn_EVP_CIPHER_CTX_free = void(*)(EVP_CIPHER_CTX*);
static fn_EVP_CIPHER_CTX_free real_EVP_CIPHER_CTX_free = nullptr;

extern "C" int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl,
                                 const unsigned char* in, int inl)
{
  RESOLVE_SYM(real_EVP_EncryptUpdate, "EVP_EncryptUpdate");
  if (!real_EVP_EncryptUpdate) return 0;
  ReentryGuard g; if (!g) return real_EVP_EncryptUpdate(ctx, out, outl, in, inl);

  log_update_event("EVP_EncryptUpdate", ctx, "enc", static_cast<size_t>(inl));
  return real_EVP_EncryptUpdate(ctx, out, outl, in, inl);
}

extern "C" int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl)
{
  RESOLVE_SYM(real_EVP_EncryptFinal_ex, "EVP_EncryptFinal_ex");
  if (!real_EVP_EncryptFinal_ex) return 0;
  ReentryGuard g; if (!g) return real_EVP_EncryptFinal_ex(ctx, out, outl);

  log_update_event("EVP_EncryptFinal_ex", ctx, "enc_final", 0);
  return real_EVP_EncryptFinal_ex(ctx, out, outl);
}

extern "C" int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl,
                                 const unsigned char* in, int inl)
{
  RESOLVE_SYM(real_EVP_DecryptUpdate, "EVP_DecryptUpdate");
  if (!real_EVP_DecryptUpdate) return 0;
  ReentryGuard g; if (!g) return real_EVP_DecryptUpdate(ctx, out, outl, in, inl);

  log_update_event("EVP_DecryptUpdate", ctx, "dec", static_cast<size_t>(inl));
  return real_EVP_DecryptUpdate(ctx, out, outl, in, inl);
}

extern "C" int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl)
{
  RESOLVE_SYM(real_EVP_DecryptFinal_ex, "EVP_DecryptFinal_ex");
  if (!real_EVP_DecryptFinal_ex) return 0;
  ReentryGuard g; if (!g) return real_EVP_DecryptFinal_ex(ctx, out, outl);

  log_update_event("EVP_DecryptFinal_ex", ctx, "dec_final", 0);
  return real_EVP_DecryptFinal_ex(ctx, out, outl);
}

extern "C" int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl,
                                const unsigned char* in, int inl)
{
  RESOLVE_SYM(real_EVP_CipherUpdate, "EVP_CipherUpdate");
  if (!real_EVP_CipherUpdate) return 0;
  ReentryGuard g; if (!g) return real_EVP_CipherUpdate(ctx, out, outl, in, inl);

  log_update_event("EVP_CipherUpdate", ctx, "cipher", static_cast<size_t>(inl));
  return real_EVP_CipherUpdate(ctx, out, outl, in, inl);
}

extern "C" int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl)
{
  RESOLVE_SYM(real_EVP_CipherFinal_ex, "EVP_CipherFinal_ex");
  if (!real_EVP_CipherFinal_ex) return 0;
  ReentryGuard g; if (!g) return real_EVP_CipherFinal_ex(ctx, out, outl);

  log_update_event("EVP_CipherFinal_ex", ctx, "cipher_final", 0);
  return real_EVP_CipherFinal_ex(ctx, out, outl);
}

extern "C" int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX* ctx)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_reset, "EVP_CIPHER_CTX_reset");
  if (!real_EVP_CIPHER_CTX_reset) return 0;
  ReentryGuard g; if (!g) return real_EVP_CIPHER_CTX_reset(ctx);

  openssl_state_forget(ctx);
  return real_EVP_CIPHER_CTX_reset(ctx);
}

extern "C" void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx)
{
  RESOLVE_SYM(real_EVP_CIPHER_CTX_free, "EVP_CIPHER_CTX_free");
  if (!real_EVP_CIPHER_CTX_free) return;
  ReentryGuard g; if (!g) { real_EVP_CIPHER_CTX_free(ctx); return; }

  openssl_state_forget(ctx);
  real_EVP_CIPHER_CTX_free(ctx);
}
