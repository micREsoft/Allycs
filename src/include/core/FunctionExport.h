#pragma once

#include <syscaller.h>

const int ALL_ERROR_SUCCESS = 0;
const int ALL_ERROR_PROCOPEN = -1;
const int ALL_ERROR_IATWRITE = -2;
const int ALL_ERROR_IATSEARCH = -3;
const int ALL_ERROR_IATNOTFOUND = -4;
const int ALL_ERROR_PIDNOTFOUND = -5;


typedef struct _GUI_DLL_PARAMETER {
	DWORD dwProcessId;
	HINSTANCE mod;
	DWORD_PTR entrypoint;
} GUI_DLL_PARAMETER, *PGUI_DLL_PARAMETER;

int InitializeGui(HINSTANCE hInstance, LPARAM param);


//function to export in DLL

extern "C" {

	BOOL DumpProcessW(const WCHAR* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR* fileResult);

	BOOL WINAPI AllycsDumpCurrentProcessW(const WCHAR* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR* fileResult);
	BOOL WINAPI AllycsDumpCurrentProcessA(const char* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char* fileResult);

	BOOL WINAPI AllycsDumpProcessW(DWORD_PTR pid, const WCHAR* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR* fileResult);
	BOOL WINAPI AllycsDumpProcessA(DWORD_PTR pid, const char* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char* fileResult);

	BOOL WINAPI AllycsRebuildFileW(const WCHAR* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);
	BOOL WINAPI AllycsRebuildFileA(const char* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);

	const WCHAR* WINAPI AllycsVersionInformationW();
	const char* WINAPI AllycsVersionInformationA();
	DWORD WINAPI AllycsVersionInformationDword();

	int WINAPI AllycsStartGui(DWORD dwProcessId, HINSTANCE mod);

	int WINAPI AllycsIatSearch(DWORD dwProcessId, DWORD_PTR* iatStart, DWORD* iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
	int WINAPI AllycsIatFixAutoW(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR* dumpFile, const WCHAR* iatFixFile);

}

/*
C/C++ Prototyps

typedef const WCHAR * (WINAPI * def_AllycsVersionInformationW)();
typedef const char * (WINAPI * def_AllycsVersionInformationA)();
typedef DWORD (WINAPI * def_AllycsVersionInformationDword)();
typedef int (WINAPI * def_AllycsIatSearch)(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
typedef int (WINAPI * def_AllycsStartGui)(DWORD dwProcessId, HINSTANCE mod);

*/
