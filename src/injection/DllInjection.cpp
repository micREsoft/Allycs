#include <injection/DllInjection.h>
#include <app/Allycs.h>
#include <core/AllycsApi.h>
#include <core/ProcessAccessHelp.h>
#pragma comment(lib, "Psapi.lib")

// Define ThreadHideFromDebugger if not already defined
#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger (THREADINFOCLASS)17
#endif

//#define DEBUG_COMMENTS

	HMODULE DllInjection::dllInjection(HANDLE hProcess, const WCHAR * filename)
	{
		LPVOID remoteMemory = nullptr;
		SIZE_T memorySize = 0;
		HANDLE hThread = nullptr;
		HMODULE hModule = nullptr;

		memorySize = (wcslen(filename) + 1) * sizeof(WCHAR);

		if (memorySize < 7)
		{
#ifdef DEBUG_COMMENTS
			Allycs::debugLog.log(L"dllInjection :: memorySize invalid");
#endif
			return nullptr;
		}

		remoteMemory = nullptr;
		SIZE_T regionSize = memorySize;
		NTSTATUS status = SysIndirectAllocateVirtualMemoryEx(
			hProcess, 
			reinterpret_cast<PVOID*>(&remoteMemory), 
			&regionSize, 
			MEM_RESERVE | MEM_COMMIT, 
			PAGE_READWRITE, 
			0, // Use 0 instead of nullptr for SIZE_T
			0
		);

		if (remoteMemory == nullptr || !NT_SUCCESS(status))
		{
#ifdef DEBUG_COMMENTS
			Allycs::debugLog.log(L"dllInjection :: VirtualAllocEx failed 0x%X", GetLastError());
#endif
			return nullptr;
		}

		if (WriteProcessMemory(hProcess, remoteMemory, filename, memorySize, &memorySize))
		{
			hThread = startRemoteThread(hProcess, LoadLibraryW, remoteMemory);

			if (hThread)
			{
				WaitForSingleObject(hThread, INFINITE);

#ifdef _WIN64

				hModule = getModuleHandleByFilename(hProcess, filename);

#else
				//returns only 32 bit values -> design bug by microsoft
				if (!GetExitCodeThread(hThread, (LPDWORD) &hModule))
				{
#ifdef DEBUG_COMMENTS
					Allycs::debugLog.log(L"dllInjection :: GetExitCodeThread failed 0x%X", GetLastError());
#endif
					hModule = nullptr;
				}
#endif

				SysIndirectClose(hThread);
			}
			else
			{
#ifdef DEBUG_COMMENTS
				Allycs::debugLog.log(L"dllInjection :: CreateRemoteThread failed 0x%X", GetLastError());
#endif
			}
		}
		else
		{
#ifdef DEBUG_COMMENTS
			Allycs::debugLog.log(L"dllInjection :: WriteProcessMemory failed 0x%X", GetLastError());
#endif
		}

		regionSize = 0;
		PVOID baseAddress = remoteMemory;
		
		NTSTATUS freeStatus = SysIndirectFreeVirtualMemory(
			hProcess, 
			&baseAddress, 
			&regionSize, 
			MEM_RELEASE
		);
		
#ifdef DEBUG_COMMENTS
		if (!NT_SUCCESS(freeStatus)) {
			Allycs::debugLog.log(L"dllInjection :: SysIndirectFreeVirtualMemory failed 0x%X", AllycsApi::NtStatusToErrorTranslator(freeStatus));
		}
#endif

		return hModule;
	}

	bool DllInjection::unloadDllInProcess(HANDLE hProcess, HMODULE hModule)
	{
		HANDLE hThread = nullptr;
		DWORD lpThreadId = 0;
		BOOL freeLibraryRet = 0;

		hThread = startRemoteThread(hProcess, FreeLibrary, hModule);

		if (hThread)
		{
			WaitForSingleObject(hThread, INFINITE);

			if (!GetExitCodeThread(hThread, (LPDWORD) &freeLibraryRet))
			{
#ifdef DEBUG_COMMENTS
				Allycs::debugLog.log(L"unloadDllInProcess :: GetExitCodeThread failed 0x%X", GetLastError());
#endif
				freeLibraryRet = 0;
			}

			SysIndirectClose(hThread);
		}
		else
		{
#ifdef DEBUG_COMMENTS
			Allycs::debugLog.log(L"unloadDllInProcess :: CreateRemoteThread failed 0x%X", GetLastError());
#endif
		}

		return freeLibraryRet != 0;
	}

	HMODULE DllInjection::getModuleHandleByFilename(HANDLE hProcess, const WCHAR * filename)
	{
		HMODULE * hMods = nullptr;
		HMODULE hModResult = nullptr;
		WCHAR target[MAX_PATH];

		DWORD numHandles = ProcessAccessHelp::getModuleHandlesFromProcess(hProcess, &hMods);
		if (numHandles == 0)
		{
			return nullptr;
		}

		for (DWORD i = 0; i < numHandles; i++)
		{
			if (GetModuleFileNameExW(hProcess, hMods[i], target, _countof(target)))
			{
				if (!_wcsicmp(target, filename))
				{
					hModResult = hMods[i];
					break;
				}
			}
			else
			{
#ifdef DEBUG_COMMENTS
				Allycs::debugLog.log(L"DllInjection::getModuleHandle :: GetModuleFileNameExW failed 0x%X", GetLastError());
#endif
			}
		}

		if (!hModResult)
		{
#ifdef DEBUG_COMMENTS
			Allycs::debugLog.log(L"DllInjection::getModuleHandle :: Handle not found");
#endif
		}

		delete [] hMods;

		return hModResult;
	}

	void DllInjection::specialThreadSettings(HANDLE hThread)
	{
		if (hThread)
		{
			if (!SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL))
			{
#ifdef DEBUG_COMMENTS
				Allycs::debugLog.log(L"specialThreadSettings :: SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL) failed 0x%X", GetLastError());
#endif
			}

			if (SysIndirectSetInformationThread)
			{
				NTSTATUS status = SysIndirectSetInformationThread(
					hThread, 
					ThreadHideFromDebugger, 
					0, // Use 0 instead of nullptr for SIZE_T
					0
				);
				
				if (!NT_SUCCESS(status))
				{
#ifdef DEBUG_COMMENTS
					Allycs::debugLog.log(L"specialThreadSettings :: SysIndirectSetInformationThread ThreadHideFromDebugger failed 0x%X", AllycsApi::NtStatusToErrorTranslator(status));
#endif
				}
			}
		}
	}

	HANDLE DllInjection::startRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
	{
		HANDLE hThread = nullptr;

		hThread = customCreateRemoteThread(hProcess, lpStartAddress, lpParameter);

		if (hThread)
		{
			specialThreadSettings(hThread);
			ResumeThread(hThread);
		}

		return hThread;
	}

	HANDLE DllInjection::customCreateRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
	{
		DWORD lpThreadId = 0;
		HANDLE hThread = nullptr;
		NTSTATUS ntStatus = 0;

		if (SysIndirectCreateThreadEx)
		{
			#define THREAD_ALL_ACCESS_VISTA_7 (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

			//for windows vista/7
			ntStatus = SysIndirectCreateThreadEx(
				&hThread, 
				THREAD_ALL_ACCESS_VISTA_7, 
				0, // ObjectAttributes - use 0 instead of nullptr for SIZE_T
				hProcess, 
				reinterpret_cast<PUSER_THREAD_START_ROUTINE>(lpStartAddress), 
				lpParameter, 
				NtCreateThreadExFlagCreateSuspended|NtCreateThreadExFlagHideFromDebugger, 
				0, 
				0, 
				0, 
				0
			);
			
			if (NT_SUCCESS(ntStatus))
			{
				return hThread;
			}
			else
			{
#ifdef DEBUG_COMMENTS
				Allycs::debugLog.log(L"customCreateRemoteThread :: NtCreateThreadEx failed 0x%X", AllycsApi::NtStatusToErrorTranslator(ntStatus));
#endif
				return nullptr;
			}
		}
		else
		{
			return CreateRemoteThread(
				hProcess, 
				0, // Use 0 instead of nullptr for security attributes 
				0, // Use 0 instead of nullptr for stack size
				reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), 
				lpParameter, 
				CREATE_SUSPENDED, 
				&lpThreadId
			);
		}
	}