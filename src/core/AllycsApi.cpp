#include "core/AllycsApi.h"
#include <thread>

def_NtErrTranslator AllycsApi::NtStatusToErrorTranslator = nullptr;

void AllycsApi::initialize()
{
    if (NtStatusToErrorTranslator)
    {
        return;
    }

    // Give the process a moment to fully initialize
    Sleep(10);

	HMODULE hModuleNtdll = GetModuleHandle(L"ntdll.dll");
    
    // If we can't get ntdll handle, try loading it explicitly
    if (!hModuleNtdll)
    {
        hModuleNtdll = LoadLibrary(L"ntdll.dll");
    }

	if (!hModuleNtdll)
	{
		return;
	}

	NtStatusToErrorTranslator = (def_NtErrTranslator)GetProcAddress(hModuleNtdll, "RtlNtStatusToDosError");
}


PPEB AllycsApi::getCurrentProcessEnvironmentBlock()
{
	return getProcessEnvironmentBlockAddress(GetCurrentProcess());
}

PPEB AllycsApi::getProcessEnvironmentBlockAddress(HANDLE processHandle)
{
    ULONG returnLength = 0;
    PROCESS_BASIC_INFORMATION processInfo{};

    NTSTATUS status = SysQueryInformationProcess(
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
