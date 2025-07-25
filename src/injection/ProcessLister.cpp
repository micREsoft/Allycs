#include "injection/ProcessLister.h"
#include "utils/SystemInformation.h"
#include "utils/Logger.h"
#include "core/ProcessAccessHelp.h"
#include <algorithm>

//#define DEBUG_COMMENTS

def_IsWow64Process ProcessLister::_IsWow64Process = nullptr;

std::vector<Process>& ProcessLister::getProcessList()
{
	return processList;
}

bool ProcessLister::isWindows64()
{
#ifdef _WIN64
	//compiled 64bit application
	return true;
#else
	//32bit exe, check wow64
	BOOL bIsWow64 = FALSE;

	//not available in all windows operating systems
	//Minimum supported client: Windows Vista, Windows XP with SP2
	//Minimum supported server: Windows Server 2008, Windows Server 2003 with SP1

	if (_IsWow64Process)
	{
		_IsWow64Process(GetCurrentProcess(), &bIsWow64);
		if (bIsWow64 != FALSE)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}
#endif	
}

//only needed in windows xp
DWORD ProcessLister::setDebugPrivileges()
{
	DWORD err = 0;
	HANDLE hToken = nullptr;
	TOKEN_PRIVILEGES Debug_Privileges{};

	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
	{
		return GetLastError();
	}

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		err = GetLastError();  
		if(hToken) 
        {
            SysClose(hToken);
        }
		return err;
	}

	Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	Debug_Privileges.PrivilegeCount = 1;

	AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, NULL, NULL);

	SysClose(hToken);
	return GetLastError();
}


/************************************************************************/
/* Check if a process is 32 or 64bit                                    */
/************************************************************************/
ProcessType ProcessLister::checkIsProcess64(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;

    if (!hProcess)
    {
        return PROCESS_MISSING_RIGHTS;
    }

	if (!isWindows64())
	{
		//32bit win can only run 32bit process
		return PROCESS_32;
	}

	_IsWow64Process(hProcess, &bIsWow64);

	if (bIsWow64 == FALSE)
	{
		//process not running under wow
		return PROCESS_64;
	} 
	else
	{
		//process running under wow -> 32bit
		return PROCESS_32;
	}
}

bool ProcessLister::getAbsoluteFilePath(HANDLE hProcess, Process* process)
{
	WCHAR processPath[MAX_PATH];
	bool retVal = false;

	wcscpy_s(process->fullPath, L"Unknown path");

	if(!hProcess)
	{
		//missing rights
		return false;
	}

	if (GetProcessImageFileNameW(hProcess, processPath, _countof(processPath)) > 0)
	{
		if (!deviceNameResolver->resolveDeviceLongNameToShort(processPath, process->fullPath))
		{
#ifdef DEBUG_COMMENTS
			Allycs::debugLog.log(L"getAbsoluteFilePath :: resolveDeviceLongNameToShort failed with path %s", processPath);
#endif
			//some virtual volumes

            if (GetModuleFileNameExW(hProcess, nullptr, process->fullPath, _countof(process->fullPath)) != 0)
            {
                retVal = true;
            }       
		}
		else
		{
			retVal = true;
		}
	}
	else
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"getAbsoluteFilePath :: GetProcessImageFileName failed %u", GetLastError());
#endif
		if (GetModuleFileNameExW(hProcess, nullptr, process->fullPath, _countof(process->fullPath)) != 0)
		{
			retVal = true;
		}
	}

	return retVal;
}

std::vector<Process>& ProcessLister::getProcessListSnapshotNative()
{
    ULONG retLength = 0;
    ULONG bufferLength = 1;
    PSYSTEM_PROCESS_INFORMATION_ALLYCS pBuffer = static_cast<PSYSTEM_PROCESS_INFORMATION_ALLYCS>(malloc(bufferLength));
    PSYSTEM_PROCESS_INFORMATION_ALLYCS pIter;
    
    if (!processList.empty())
    {
        //clear elements, but keep reversed memory
        processList.clear();
    }
    else
    {
        //first time, reserve memory
        processList.reserve(34);
    }

    NTSTATUS status = SysQuerySystemInformation(
        SystemProcessInformation, 
        pBuffer, 
        bufferLength, 
        &retLength
    );
    
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(pBuffer);
        bufferLength = retLength + sizeof(SYSTEM_PROCESS_INFORMATION_ALLYCS);
        pBuffer = static_cast<PSYSTEM_PROCESS_INFORMATION_ALLYCS>(malloc(bufferLength));
        if (!pBuffer)
            return processList;

        status = SysQuerySystemInformation(
            SystemProcessInformation, 
            pBuffer, 
            bufferLength, 
            &retLength
        );
        
        if (!NT_SUCCESS(status))
        {
            free(pBuffer);
            return processList;
        }
    }
    else
    {
        free(pBuffer);
        return processList;
    }

    pIter = pBuffer;

    while(TRUE)
    {
        if (pIter->UniqueProcessId > reinterpret_cast<HANDLE>(4)) //small filter
        {
            handleProcessInformationAndAddToList(pIter);
        }

        if (pIter->NextEntryOffset == 0)
        {
            break;
        }
        else
        {
            pIter = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_ALLYCS>(
                reinterpret_cast<DWORD_PTR>(pIter) + 
                static_cast<DWORD_PTR>(pIter->NextEntryOffset)
            );
        }
    }

    std::reverse(processList.begin(), processList.end()); //reverse process list

    free(pBuffer);
    return processList;
}

void ProcessLister::handleProcessInformationAndAddToList(PSYSTEM_PROCESS_INFORMATION_ALLYCS pProcess)
{
    Process process;
    WCHAR tempProcessName[MAX_PATH*2] = {0};

    process.PID = HandleToULong(pProcess->UniqueProcessId);

    HANDLE hProcess = ProcessAccessHelp::AllycsOpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, process.PID);

    if (hProcess)
    {
        ProcessType processType = checkIsProcess64(hProcess);

#ifdef _WIN64
        if (processType == PROCESS_64)
#else
        if (processType == PROCESS_32)
#endif
        {
            process.sessionId = pProcess->SessionId;

            memcpy(tempProcessName, pProcess->ImageName.Buffer, pProcess->ImageName.Length);
            wcscpy_s(process.filename, tempProcessName);

            getAbsoluteFilePath(hProcess, &process);
            process.pebAddress = getPebAddressFromProcess(hProcess);
            getProcessImageInformation(hProcess, &process);

            processList.push_back(process);
        }
        SysClose(hProcess);
    }
}

void ProcessLister::getProcessImageInformation(HANDLE hProcess, Process* process)
{
    DWORD_PTR readImagebase = 0;
    process->imageBase = 0;
    process->imageSize = 0;

    if (hProcess && process->pebAddress)
    {
        PEB_CURRENT* peb = reinterpret_cast<PEB_CURRENT*>(process->pebAddress);

        if (ReadProcessMemory(hProcess, &peb->ImageBaseAddress, &readImagebase, sizeof(DWORD_PTR), nullptr))
        {
            process->imageBase = readImagebase;
            process->imageSize = static_cast<DWORD>(ProcessAccessHelp::getSizeOfImageProcess(hProcess, process->imageBase));
        }
    }
}

DWORD_PTR ProcessLister::getPebAddressFromProcess(HANDLE hProcess)
{
    if (hProcess)
    {
        ULONG RequiredLen = 0;
        void * PebAddress = nullptr;
        PROCESS_BASIC_INFORMATION myProcessBasicInformation[5]{};

        NTSTATUS status = SysQueryInformationProcess(
            hProcess, 
            ProcessBasicInformation, 
            myProcessBasicInformation, 
            sizeof(PROCESS_BASIC_INFORMATION), 
            &RequiredLen
        );
        
        if (NT_SUCCESS(status))
        {
            PebAddress = reinterpret_cast<void*>(myProcessBasicInformation->PebBaseAddress);
        }
        else
        {
            status = SysQueryInformationProcess(
                hProcess, 
                ProcessBasicInformation, 
                myProcessBasicInformation, 
                RequiredLen, 
                &RequiredLen
            );
            
            if (NT_SUCCESS(status))
            {
                PebAddress = reinterpret_cast<void*>(myProcessBasicInformation->PebBaseAddress);
            }
        }

        return reinterpret_cast<DWORD_PTR>(PebAddress);
    }

    return 0;
}
