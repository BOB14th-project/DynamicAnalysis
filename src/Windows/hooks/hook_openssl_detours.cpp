// hook_openssl_detours.cpp - Windows OpenSSL hooking using Microsoft Detours
#include "pch.h"
#include "output.h"
#include "reentry_guard.h"
#include "hook_openssl_state.h"

#include <windows.h>
#include <detours.h>
#include <openssl/evp.h>

typedef struct engine_st ENGINE;

static constexpr const char* SURFACE = "openssl";

// ---- OpenSSL cipher utilities ----
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

// ---- Original function pointers (to be detoured) ----
static int (WINAPI* TrueEVP_EncryptInit_ex)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*) = EVP_EncryptInit_ex;
static int (WINAPI* TrueEVP_DecryptInit_ex)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*) = EVP_DecryptInit_ex;
static int (WINAPI* TrueEVP_CipherInit_ex)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*, int) = EVP_CipherInit_ex;
static int (WINAPI* TrueEVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX*, int, int, void*) = EVP_CIPHER_CTX_ctrl;

// ---- Common logging helper ----
static inline void log_init_ex(const char* api, const char* dir,
                              EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type,
                              const unsigned char* key, const unsigned char* iv)
{
    const EVP_CIPHER* c = type ? type : cipher_from_ctx(ctx);
    const char* cname = cipher_name(c);
    int klen = (key && c) ? EVP_CIPHER_key_length(c) : 0;
    int ivlen = (iv && c) ? EVP_CIPHER_iv_length(c) : 0;

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

// ---- Detoured functions ----
static int WINAPI DetourEVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx,
                                           const EVP_CIPHER* type,
                                           ENGINE* impl,
                                           const unsigned char* key,
                                           const unsigned char* iv)
{
    ReentryGuard guard;
    if (guard) {
        log_init_ex("EVP_EncryptInit_ex", "enc", ctx, type, key, iv);
    }
    return TrueEVP_EncryptInit_ex(ctx, type, impl, key, iv);
}

static int WINAPI DetourEVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx,
                                          const EVP_CIPHER* type,
                                          ENGINE* impl,
                                          const unsigned char* key,
                                          const unsigned char* iv)
{
    ReentryGuard guard;
    if (guard) {
        log_init_ex("EVP_DecryptInit_ex", "dec", ctx, type, key, iv);
    }
    return TrueEVP_DecryptInit_ex(ctx, type, impl, key, iv);
}

static int WINAPI DetourEVP_CipherInit_ex(EVP_CIPHER_CTX* ctx,
                                         const EVP_CIPHER* type,
                                         ENGINE* impl,
                                         const unsigned char* key,
                                         const unsigned char* iv,
                                         int enc)
{
    ReentryGuard guard;
    if (guard) {
        const char* dir = (enc == 1) ? "enc" : (enc == 0) ? "dec" : "cipher";
        log_init_ex("EVP_CipherInit_ex", dir, ctx, type, key, iv);
    }
    return TrueEVP_CipherInit_ex(ctx, type, impl, key, iv, enc);
}

static int WINAPI DetourEVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr)
{
    ReentryGuard guard;

    // Call original first to avoid corrupting state
    int result = TrueEVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);

    if (guard) {
        // Log GCM tag extraction (EVP_CTRL_GCM_GET_TAG = 16)
        if (type == 16 && ptr && arg > 0) { // EVP_CTRL_GCM_GET_TAG
            OpenSSLState st;
            const char* cname = nullptr;
            if (openssl_state_lookup(ctx, st)) {
                cname = st.cipher_name.c_str();
            } else {
                const EVP_CIPHER* cipher = cipher_from_ctx(ctx);
                cname = cipher ? cipher_name(cipher) : nullptr;
            }

            ndjson_log_key_event(
                SURFACE, "EVP_CIPHER_CTX_ctrl", "tag_get", cname,
                nullptr, 0, nullptr, 0,
                static_cast<const unsigned char*>(ptr), arg);
        }
    }

    return result;
}

// ---- Detours initialization ----
extern "C" {

BOOL InstallOpenSSLHooks()
{
    BOOL success = TRUE;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)TrueEVP_EncryptInit_ex, DetourEVP_EncryptInit_ex);
    DetourAttach(&(PVOID&)TrueEVP_DecryptInit_ex, DetourEVP_DecryptInit_ex);
    DetourAttach(&(PVOID&)TrueEVP_CipherInit_ex, DetourEVP_CipherInit_ex);
    DetourAttach(&(PVOID&)TrueEVP_CIPHER_CTX_ctrl, DetourEVP_CIPHER_CTX_ctrl);

    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        success = FALSE;
    }

    return success;
}

BOOL UninstallOpenSSLHooks()
{
    BOOL success = TRUE;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)TrueEVP_EncryptInit_ex, DetourEVP_EncryptInit_ex);
    DetourDetach(&(PVOID&)TrueEVP_DecryptInit_ex, DetourEVP_DecryptInit_ex);
    DetourDetach(&(PVOID&)TrueEVP_CipherInit_ex, DetourEVP_CipherInit_ex);
    DetourDetach(&(PVOID&)TrueEVP_CIPHER_CTX_ctrl, DetourEVP_CIPHER_CTX_ctrl);

    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        success = FALSE;
    }

    return success;
}

} // extern "C"