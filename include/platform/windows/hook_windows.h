// hook_windows.h - Windows-specific hooking interface
#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hook installation/removal functions
BOOL InstallOpenSSLHooks();
BOOL UninstallOpenSSLHooks();

#ifdef HAVE_WINDOWS_LIBSODIUM
BOOL InstallLibsodiumHooks();
BOOL UninstallLibsodiumHooks();
#endif

// Windows-specific initialization
BOOL InitializeWindowsHooks();
void CleanupWindowsHooks();

#ifdef __cplusplus
}
#endif
