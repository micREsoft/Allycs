#include <core/AllycsApi.h>
#include <thread>

def_NtErrTranslator AllycsApi::NtStatusToErrorTranslator = nullptr;
HMODULE AllycsApi::hSysCallerDll = nullptr;
InitializeResolver_t AllycsApi::InitializeResolver = nullptr;
CleanupResolver_t AllycsApi::CleanupResolver = nullptr;

bool AllycsApi::initialize()
{
    if (NtStatusToErrorTranslator)
    {
        return true; // Already initialized
    }

    // Give the process a moment to fully initialize
    Sleep(10);

    // Load SysCaller.dll for indirect syscalls
    hSysCallerDll = LoadLibrary(L"SysCaller.dll");
    if (!hSysCallerDll)
    {
        // Try to find it in the current directory
        WCHAR currentDir[MAX_PATH];
        GetCurrentDirectory(MAX_PATH, currentDir);
        wcscat_s(currentDir, L"\\SysCaller.dll");

        hSysCallerDll = LoadLibrary(currentDir);
        if (!hSysCallerDll)
        {
            return false; // Failed to load DLL
        }
    }

    // Get function pointers
    InitializeResolver = (InitializeResolver_t)GetProcAddress(hSysCallerDll, "InitializeResolver");
    CleanupResolver = (CleanupResolver_t)GetProcAddress(hSysCallerDll, "CleanupResolver");

    if (!InitializeResolver || !CleanupResolver)
    {
        FreeLibrary(hSysCallerDll);
        hSysCallerDll = nullptr;
        return false;
    }

    // Initialize the resolver
    if (!InitializeResolver())
    {
        FreeLibrary(hSysCallerDll);
        hSysCallerDll = nullptr;
        return false;
    }

    // Load ntdll.dll for error translation
    HMODULE hModuleNtdll = GetModuleHandle(L"ntdll.dll");

    // If we can't get ntdll handle, try loading it explicitly
    if (!hModuleNtdll)
    {
        hModuleNtdll = LoadLibrary(L"ntdll.dll");
    }

    if (!hModuleNtdll)
    {
        return false;
    }

    NtStatusToErrorTranslator = (def_NtErrTranslator)GetProcAddress(hModuleNtdll, "RtlNtStatusToDosError");
    return NtStatusToErrorTranslator != nullptr;
}

void AllycsApi::cleanup()
{
    if (CleanupResolver)
    {
        CleanupResolver();
    }

    if (hSysCallerDll)
    {
        FreeLibrary(hSysCallerDll);
        hSysCallerDll = nullptr;
    }

    InitializeResolver = nullptr;
    CleanupResolver = nullptr;
}


PPEB AllycsApi::getCurrentProcessEnvironmentBlock()
{
	return getProcessEnvironmentBlockAddress(GetCurrentProcess());
}

PPEB AllycsApi::getProcessEnvironmentBlockAddress(HANDLE processHandle)
{
    ULONG returnLength = 0;
    PROCESS_BASIC_INFORMATION processInfo{};

    NTSTATUS status = SysIndirectQueryInformationProcess(
        processHandle,
        (PROCESSINFOCLASS)ProcessBasicInformation,
        &processInfo,
        sizeof(processInfo),
        &returnLength
    );

    if (NT_SUCCESS(status) && returnLength == sizeof(processInfo))
        return processInfo.PebBaseAddress;

    return nullptr;
}
