//#include <vld.h> // Visual Leak Detector
#include <atlbase.h>       // base ATL classes
#include <atlapp.h>        // base WTL classes
#include <core/Architecture.h>
#include <app/MainGui.h>
#include <app/Allycs.h>

CAppModule _Module;
MainGui* pMainGui = NULL; // for Logger
HINSTANCE hDllModule = 0;
bool IsDllMode = false;

LONG WINAPI HandleUnknownException(struct _EXCEPTION_POINTERS *ExceptionInfo);
void AddExceptionHandler();
void RemoveExceptionHandler();
int InitializeGui(HINSTANCE hInstance, LPARAM param);

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	// Add exception handler first
	AddExceptionHandler();

	// Ensure Windows APIs are fully initialized
	CoInitialize(NULL);
	AtlInitCommonControls(ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES);

	// Now initialize our application
	return InitializeGui(hInstance, (LPARAM)0);
}

int InitializeGui(HINSTANCE hInstance, LPARAM param)
{
	// CoInitialize already called in _tWinMain
	// AtlInitCommonControls already called in _tWinMain

	Allycs::initAsGuiApp();

	IsDllMode = false;

	HRESULT hRes = _Module.Init(NULL, hInstance);
	ATLASSERT(SUCCEEDED(hRes));

	

	int nRet = 0;
	// BLOCK: Run application
	{
		MainGui dlgMain;
		pMainGui = &dlgMain; // o_O

		CMessageLoop loop;
		_Module.AddMessageLoop(&loop);

		dlgMain.Create(GetDesktopWindow(), param);

		dlgMain.ShowWindow(SW_SHOW);

		loop.Run();
	}

	_Module.Term();
	CoUninitialize();

	// Cleanup SysCaller resources
	Allycs::cleanup();

	return nRet;
}

void InitializeDll(HINSTANCE hinstDLL)
{
	hDllModule = hinstDLL;
	IsDllMode = true;
	Allycs::initAsDll();
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	// Perform actions based on the reason for calling.
	switch(fdwReason) 
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		AddExceptionHandler();
		InitializeDll(hinstDLL);
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		RemoveExceptionHandler();
		Allycs::cleanup();
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

LPTOP_LEVEL_EXCEPTION_FILTER oldFilter;

void AddExceptionHandler()
{
	oldFilter = SetUnhandledExceptionFilter(HandleUnknownException);
}
void RemoveExceptionHandler()
{
	SetUnhandledExceptionFilter(oldFilter);
}

LONG WINAPI HandleUnknownException(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	WCHAR registerInfo[220];
	WCHAR filepath[MAX_PATH] = {0};
	WCHAR file[MAX_PATH] = {0};
	WCHAR message[MAX_PATH + 400 + _countof(registerInfo)];
	WCHAR osInfo[100];
	DWORD_PTR baseAddress = 0;
	DWORD_PTR address = (DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;

	wcscpy_s(filepath, L"unknown");
	wcscpy_s(file, L"unknown");

	if (GetMappedFileNameW(GetCurrentProcess(), (LPVOID)address, filepath, _countof(filepath)) > 0)
	{
		WCHAR *temp = wcsrchr(filepath, '\\');
		if (temp)
		{
			temp++;
			wcscpy_s(file, temp);
		}
	}

	swprintf_s(osInfo, _countof(osInfo), TEXT("Exception! Please report it! OS: %X"), GetVersion());

	DWORD_PTR moduleBase = (DWORD_PTR)GetModuleHandleW(file);
	
	// Get exception name
	const WCHAR* exceptionName = L"UNKNOWN";
	switch(ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		exceptionName = L"ACCESS_VIOLATION";
		break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		exceptionName = L"ARRAY_BOUNDS_EXCEEDED";
		break;
	case EXCEPTION_BREAKPOINT:
		exceptionName = L"BREAKPOINT";
		break;
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		exceptionName = L"DATATYPE_MISALIGNMENT";
		break;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		exceptionName = L"FLT_DENORMAL_OPERAND";
		break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		exceptionName = L"FLT_DIVIDE_BY_ZERO";
		break;
	case EXCEPTION_FLT_INEXACT_RESULT:
		exceptionName = L"FLT_INEXACT_RESULT";
		break;
	case EXCEPTION_FLT_INVALID_OPERATION:
		exceptionName = L"FLT_INVALID_OPERATION";
		break;
	case EXCEPTION_FLT_OVERFLOW:
		exceptionName = L"FLT_OVERFLOW";
		break;
	case EXCEPTION_FLT_STACK_CHECK:
		exceptionName = L"FLT_STACK_CHECK";
		break;
	case EXCEPTION_FLT_UNDERFLOW:
		exceptionName = L"FLT_UNDERFLOW";
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		exceptionName = L"ILLEGAL_INSTRUCTION";
		break;
	case EXCEPTION_IN_PAGE_ERROR:
		exceptionName = L"IN_PAGE_ERROR";
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		exceptionName = L"INT_DIVIDE_BY_ZERO";
		break;
	case EXCEPTION_INT_OVERFLOW:
		exceptionName = L"INT_OVERFLOW";
		break;
	case EXCEPTION_INVALID_DISPOSITION:
		exceptionName = L"INVALID_DISPOSITION";
		break;
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		exceptionName = L"NONCONTINUABLE_EXCEPTION";
		break;
	case EXCEPTION_PRIV_INSTRUCTION:
		exceptionName = L"PRIV_INSTRUCTION";
		break;
	case EXCEPTION_SINGLE_STEP:
		exceptionName = L"SINGLE_STEP";
		break;
	case EXCEPTION_STACK_OVERFLOW:
		exceptionName = L"STACK_OVERFLOW";
		break;
	}
	
	swprintf_s(message, _countof(message), TEXT("Exception: %s (0x%08X)\r\nExceptionFlags %08X\r\nNumberParameters %08X\r\nExceptionAddress VA ")TEXT(PRINTF_DWORD_PTR_FULL_S)TEXT(" - Base ")TEXT(PRINTF_DWORD_PTR_FULL_S)TEXT("\r\nExceptionAddress module %s\r\n\r\n"), 
	exceptionName,
	ExceptionInfo->ExceptionRecord->ExceptionCode,
	ExceptionInfo->ExceptionRecord->ExceptionFlags, 
	ExceptionInfo->ExceptionRecord->NumberParameters, 
	address,
	moduleBase,
	file);

#ifdef _WIN64
	swprintf_s(registerInfo, _countof(registerInfo),TEXT("rax=0x%p, rbx=0x%p, rdx=0x%p, rcx=0x%p, rsi=0x%p, rdi=0x%p, rbp=0x%p, rsp=0x%p, rip=0x%p"),
		ExceptionInfo->ContextRecord->Rax,
		ExceptionInfo->ContextRecord->Rbx,
		ExceptionInfo->ContextRecord->Rdx,
		ExceptionInfo->ContextRecord->Rcx,
		ExceptionInfo->ContextRecord->Rsi,
		ExceptionInfo->ContextRecord->Rdi,
		ExceptionInfo->ContextRecord->Rbp,
		ExceptionInfo->ContextRecord->Rsp,
		ExceptionInfo->ContextRecord->Rip
		);
#else
	swprintf_s(registerInfo, _countof(registerInfo),TEXT("eax=0x%p, ebx=0x%p, edx=0x%p, ecx=0x%p, esi=0x%p, edi=0x%p, ebp=0x%p, esp=0x%p, eip=0x%p"),
		ExceptionInfo->ContextRecord->Eax,
		ExceptionInfo->ContextRecord->Ebx,
		ExceptionInfo->ContextRecord->Edx,
		ExceptionInfo->ContextRecord->Ecx,
		ExceptionInfo->ContextRecord->Esi,
		ExceptionInfo->ContextRecord->Edi,
		ExceptionInfo->ContextRecord->Ebp,
		ExceptionInfo->ContextRecord->Esp,
		ExceptionInfo->ContextRecord->Eip
		);
#endif

	wcscat_s(message, _countof(message), registerInfo);

	// Add additional info for access violations
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && 
		ExceptionInfo->ExceptionRecord->NumberParameters >= 2)
	{
		WCHAR avInfo[100];
		DWORD_PTR avAddress = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
		DWORD avType = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
		
		swprintf_s(avInfo, _countof(avInfo), 
			L"\r\n\r\nAccess Violation: %s memory at address 0x%p", 
			avType ? (avType == 1 ? L"writing to" : L"executing") : L"reading from",
			avAddress);
		
		wcscat_s(message, _countof(message), avInfo);
	}

	MessageBox(0, message, osInfo, MB_ICONERROR);

	return EXCEPTION_CONTINUE_SEARCH;
}
