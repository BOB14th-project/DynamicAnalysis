// windows_hook_dll.cpp - Windows DLL entry point for hooking
#include "pch.h"
#include "hook_common.h"
#include "hooks/hook_windows.h"

#include <windows.h>
#include <detours.h>

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Disable DLL_THREAD_ATTACH/DETACH notifications for performance
        DisableThreadLibraryCalls(hModule);

        // Initialize common hook runtime
        hook_runtime_init();

        // Install OpenSSL hooks
        if (!InitializeWindowsHooks()) {
            return FALSE;
        }
        break;

    case DLL_PROCESS_DETACH:
        // Cleanup hooks
        CleanupWindowsHooks();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        // These are disabled by DisableThreadLibraryCalls
        break;
    }
    return TRUE;
}

// Initialize all Windows hooks
BOOL InitializeWindowsHooks()
{
    BOOL success = TRUE;

    // Install OpenSSL hooks
    if (!InstallOpenSSLHooks()) {
        success = FALSE;
    }

    return success;
}

// Cleanup all Windows hooks
void CleanupWindowsHooks()
{
    UninstallOpenSSLHooks();
}

// Export functions for manual hook control
extern "C" {
    __declspec(dllexport) BOOL InstallHooks()
    {
        return InitializeWindowsHooks();
    }

    __declspec(dllexport) void RemoveHooks()
    {
        CleanupWindowsHooks();
    }
}