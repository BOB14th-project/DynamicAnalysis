// src/platform/mac/hooks/mac_hook_openssl_core.cpp - macOS version
#include "common/pch.h"
#include "common/output.h"
#include "common/reentry_guard.h"
#include "common/hook_openssl_state.h"

#include <dlfcn.h>
#include <openssl/evp.h>

typedef struct engine_st ENGINE;

// Convenience macro to place our replacements in the interpose section.
#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) \
    static const struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };
#endif
static constexpr const char* SURFACE = "openssl";

// ---- 유틸 함수 ----
static inline const char* cipher_name(const EVP_CIPHER* c) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  return c ? EVP_CIPHER_get0_name(c) : nullptr;
#else
  return c ? OBJ_nid2sn(EVP_CIPHER_nid(c)) : nullptr;
#endif
}

static inline const EVP_CIPHER* cipher_from_ctx(const EVP_CIPHER_CTX* ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  return ctx ? EVP_CIPHER_CTX_get0_cipher(ctx) : nullptr;
#else
  return ctx ? EVP_CIPHER_CTX_cipher(ctx) : nullptr;
#endif
}

// ---- 공통 로깅 헬퍼 ----
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

  if (std::getenv("HOOK_VERBOSE")) {
    fprintf(stderr, "[hook_macos] logged cipher=%s keylen=%d ivlen=%d\n",
            cname ? cname : "(null)", klen, ivlen);
  }
}

// Thread-local storage to prevent recursion
static __thread int in_hook = 0;

// Original function types
using fn_EVP_EncryptInit_ex = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);
using fn_EVP_DecryptInit_ex = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);
using fn_EVP_CipherInit_ex  = int(*)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*, int);

// Hook functions with C linkage
extern "C" {

int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                       ENGINE* eng, const unsigned char* key, const unsigned char* iv)
{
  if (in_hook) {
    // Prevent recursion - call original directly
    static fn_EVP_EncryptInit_ex original = nullptr;
    if (!original) original = (fn_EVP_EncryptInit_ex)dlsym(RTLD_NEXT, "EVP_EncryptInit_ex");
    if (original) return original(ctx, type, eng, key, iv);
    return 0;
  }

  in_hook = 1;

  // Get original function
  static fn_EVP_EncryptInit_ex original = nullptr;
  if (!original) {
    original = (fn_EVP_EncryptInit_ex)dlsym(RTLD_NEXT, "EVP_EncryptInit_ex");
  }

  if (!original) {
    in_hook = 0;
    return 0;
  }

  // Log before calling original
  log_init_ex("EVP_EncryptInit_ex", "enc", ctx, type, key, iv);

  // Call original
  int result = original(ctx, type, eng, key, iv);

  in_hook = 0;
  return result;
}
DYLD_INTERPOSE(EVP_EncryptInit_ex, EVP_EncryptInit_ex)

int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                       ENGINE* eng, const unsigned char* key, const unsigned char* iv)
{
  if (in_hook) {
    static fn_EVP_DecryptInit_ex original = nullptr;
    if (!original) original = (fn_EVP_DecryptInit_ex)dlsym(RTLD_NEXT, "EVP_DecryptInit_ex");
    if (original) return original(ctx, type, eng, key, iv);
    return 0;
  }

  in_hook = 1;

  static fn_EVP_DecryptInit_ex original = nullptr;
  if (!original) {
    original = (fn_EVP_DecryptInit_ex)dlsym(RTLD_NEXT, "EVP_DecryptInit_ex");
  }

  if (!original) {
    in_hook = 0;
    return 0;
  }

  log_init_ex("EVP_DecryptInit_ex", "dec", ctx, type, key, iv);

  int result = original(ctx, type, eng, key, iv);

  in_hook = 0;
  return result;
}
DYLD_INTERPOSE(EVP_DecryptInit_ex, EVP_DecryptInit_ex)

int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                      ENGINE* eng, const unsigned char* key, const unsigned char* iv, int enc)
{
  if (in_hook) {
    static fn_EVP_CipherInit_ex original = nullptr;
    if (!original) original = (fn_EVP_CipherInit_ex)dlsym(RTLD_NEXT, "EVP_CipherInit_ex");
    if (original) return original(ctx, type, eng, key, iv, enc);
    return 0;
  }

  in_hook = 1;

  static fn_EVP_CipherInit_ex original = nullptr;
  if (!original) {
    original = (fn_EVP_CipherInit_ex)dlsym(RTLD_NEXT, "EVP_CipherInit_ex");
  }

  if (!original) {
    in_hook = 0;
    return 0;
  }

  log_init_ex("EVP_CipherInit_ex", enc ? "enc" : "dec", ctx, type, key, iv);

  int result = original(ctx, type, eng, key, iv, enc);

  in_hook = 0;
  return result;
}
DYLD_INTERPOSE(EVP_CipherInit_ex, EVP_CipherInit_ex)

} // extern "C"
