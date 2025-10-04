#pragma once

#include <syscaller.h>

// ALLYCS STRUCTS

typedef struct _IO_STATUS_BLOCK_ALLYCS {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK_ALLYCS, * PIO_STATUS_BLOCK_ALLYCS;

typedef struct _FILE_NAME_INFORMATION_ALLYCS { // Information Classes 9 and 21
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION_ALLYCS;

typedef struct _UNICODE_STRING_ALLYCS {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING_ALLYCS, * PUNICODE_STRING_ALLYCS;

typedef struct _CLIENT_ID_ALLYCS {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID_ALLYCS, * PCLIENT_ID_ALLYCS;

typedef struct _OBJECT_ATTRIBUTES_ALLYCS
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING_ALLYCS ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_ALLYCS, * POBJECT_ATTRIBUTES_ALLYCS;

typedef struct _MEMORY_REGION_INFORMATION_ALLYCS
{
	PVOID AllocationBase; //Imagebase
	ULONG AllocationProtect;
	ULONG RegionType;
	SIZE_T RegionSize; //Size of image
} MEMORY_REGION_INFORMATION_ALLYCS, * PMEMORY_REGION_INFORMATION_ALLYCS;

typedef struct _PEB_LDR_DATA_ALLYCS {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA_ALLYCS, * PPEB_LDR_DATA_ALLYCS;

typedef struct _RTL_USER_PROCESS_PARAMETERS_ALLYCS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING_ALLYCS ImagePathName;
	UNICODE_STRING_ALLYCS CommandLine;
} RTL_USER_PROCESS_PARAMETERS_ALLYCS, * PRTL_USER_PROCESS_PARAMETERS_ALLYCS;

typedef struct _PEB_ALLYCS {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA_ALLYCS          Ldr;
	PRTL_USER_PROCESS_PARAMETERS_ALLYCS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID						  PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB_ALLYCS, * PPEB_ALLYCS;

typedef struct _PROCESS_BASIC_INFORMATION_ALLYCS {
	PVOID Reserved1;
	PPEB_ALLYCS PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_ALLYCS;


typedef struct _MEMORY_WORKING_SET_LIST_ALLYCS
{
	ULONG	NumberOfPages;
	ULONG	WorkingSetList[1];
} MEMORY_WORKING_SET_LIST_ALLYCS, * PMEMORY_WORKING_SET_LIST_ALLYCS;

typedef struct _MEMORY_SECTION_NAME_ALLYCS
{
	UNICODE_STRING_ALLYCS	SectionFileName;
} MEMORY_SECTION_NAME_ALLYCS, * PMEMORY_SECTION_NAME_ALLYCS;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION_ALLYCS
{
	ULONG SessionId;
	ULONG SizeOfBuf;
	PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION_ALLYCS, * PSYSTEM_SESSION_PROCESS_INFORMATION_ALLYCS;

typedef struct _SYSTEM_THREAD_INFORMATION_ALLYCS
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID_ALLYCS ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_ALLYCS, * PSYSTEM_THREAD_INFORMATION_ALLYCS;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION_ALLYCS
{
	SYSTEM_THREAD_INFORMATION_ALLYCS ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress; /* This is only filled in on Vista and above */
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION_ALLYCS, * PSYSTEM_EXTENDED_THREAD_INFORMATION_ALLYCS;

typedef struct _SYSTEM_PROCESS_INFORMATION_ALLYCS
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING_ALLYCS ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION_ALLYCS Threads[1];
} SYSTEM_PROCESS_INFORMATION_ALLYCS, * PSYSTEM_PROCESS_INFORMATION_ALLYCS;

// ALLYCS ENUM CLASSES
enum class SYSTEM_INFORMATION_CLASS_ALLYCS {

	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation2,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation

};

enum class FILE_INFORMATION_CLASS_ALLYCS {
	FileNameInformation = 9,
};
using PFILE_INFORMATION_CLASS_ALLYCS = FILE_INFORMATION_CLASS_ALLYCS*;

enum class OBJECT_INFORMATION_CLASS_ALLYCS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
};
using POBJECT_INFORMATION_CLASS_ALLYCS = OBJECT_INFORMATION_CLASS_ALLYCS*;

enum class _THREADINFOCLASS_ALLYCS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
};

//
// Memory Information Classes for NtQueryVirtualMemory
//
enum class _MEMORY_INFORMATION_CLASS_ALLYCS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation, //MemorySectionName, UNICODE_STRING, Wrapper: GetMappedFileNameW
	MemoryRegionInformation, //MemoryBasicVlmInformation, MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation
};

enum class _PROCESSINFOCLASS_ALLYCS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessResourceManagement,
	ProcessCookie,
	ProcessImageInformation,
	MaxProcessInfoClass
};