#pragma once
#include <syscaller.h>
#include "sysTypes.h"
#include "sysExternals.h"
#ifdef _WIN64 /* only compile on 64bit systems */

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS SysIndirectAllocateVirtualMemoryEx(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters OPTIONAL,
    ULONG ExtendedParameterCount
);

NTSTATUS SysIndirectClose(
    HANDLE Handle
);

NTSTATUS SysIndirectCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    PUSER_THREAD_START_ROUTINE StartRoutine,
    PVOID Argument OPTIONAL,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

NTSTATUS SysIndirectFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

NTSTATUS SysIndirectOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID * ClientId OPTIONAL
);

NTSTATUS SysIndirectOpenSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS SysIndirectProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

NTSTATUS SysIndirectQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL
);

NTSTATUS SysIndirectQuerySymbolicLinkObject(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength OPTIONAL
);

NTSTATUS SysIndirectQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS SysIndirectQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength OPTIONAL
);

NTSTATUS SysIndirectResumeProcess(
    HANDLE ProcessHandle
);

NTSTATUS SysIndirectSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

NTSTATUS SysIndirectSuspendProcess(
    HANDLE ProcessHandle
);

NTSTATUS SysIndirectTerminateProcess(
    HANDLE ProcessHandle OPTIONAL,
    NTSTATUS ExitStatus
);

NTSTATUS SysIndirectUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress OPTIONAL
);

#ifdef __cplusplus
}
#endif

#endif

