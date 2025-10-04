#include <core/PeParser.h>
#include <core/ProcessAccessHelp.h>
#include <app/Allycs.h>
#include <core/Architecture.h>
#include <core/FunctionExport.h>
#include <injection/ProcessLister.h>
#include <core/ApiReader.h>
#include <core/IATSearch.h>
#include <core/ImportRebuilder.h>

extern HINSTANCE hDllModule;

const WCHAR * WINAPI AllycsVersionInformationW()
{
	return APPNAME L" " ARCHITECTURE L" " APPVERSION;
}

const char * WINAPI AllycsVersionInformationA()
{
	return APPNAME_S " " ARCHITECTURE_S " " APPVERSION_S;
}

DWORD WINAPI AllycsVersionInformationDword()
{
	return APPVERSIONDWORD;
}

BOOL DumpProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	PeParser * peFile = 0;

	if (fileToDump)
	{
		peFile = new PeParser(fileToDump, true);
	}
	else
	{
		peFile = new PeParser(imagebase, true);
	}

	bool result = peFile->dumpProcess(imagebase, entrypoint, fileResult);

	delete peFile;
	return result;
}

BOOL WINAPI AllycsRebuildFileW(const WCHAR * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{
	if (createBackup)
	{
		if (!ProcessAccessHelp::createBackupFile(fileToRebuild))
		{
			return FALSE;
		}
	}

	PeParser peFile(fileToRebuild, true);
	if (peFile.readPeSectionsFromFile())
	{
		peFile.setDefaultFileAlignment();
		if (removeDosStub)
		{
			peFile.removeDosStub();
		}
		peFile.alignAllSectionHeaders();
		peFile.fixPeHeader();

		if (peFile.savePeFileToDisk(fileToRebuild))
		{
			if (updatePeHeaderChecksum)
			{
				PeParser::updatePeHeaderChecksum(fileToRebuild, (DWORD)ProcessAccessHelp::getFileSize(fileToRebuild));
			}
			return TRUE;
		}
	}

	return FALSE;
}

BOOL WINAPI AllycsRebuildFileA(const char * fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)
{
	WCHAR fileToRebuildW[MAX_PATH];
	if (MultiByteToWideChar(CP_ACP, 0, fileToRebuild, -1, fileToRebuildW, _countof(fileToRebuildW)) == 0)
	{
		return FALSE;
	}

	return AllycsRebuildFileW(fileToRebuildW, removeDosStub, updatePeHeaderChecksum, createBackup);
}

BOOL WINAPI AllycsDumpCurrentProcessW(const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	ProcessAccessHelp::setCurrentProcessAsTarget();

	return DumpProcessW(fileToDump, imagebase, entrypoint, fileResult);
}

BOOL WINAPI AllycsDumpProcessW(DWORD_PTR pid, const WCHAR * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR * fileResult)
{
	if (ProcessAccessHelp::openProcessHandle((DWORD)pid))
	{
		return DumpProcessW(fileToDump, imagebase, entrypoint, fileResult);
	}
	else
	{
		return FALSE;
	}	
}

BOOL WINAPI AllycsDumpCurrentProcessA(const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
	WCHAR fileToDumpW[MAX_PATH];
	WCHAR fileResultW[MAX_PATH];

	if (fileResult == 0)
	{
		return FALSE;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fileResult, -1, fileResultW, _countof(fileResultW)) == 0)
	{
		return FALSE;
	}

	if (fileToDump != 0)
	{
		if (MultiByteToWideChar(CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof(fileToDumpW)) == 0)
		{
			return FALSE;
		}

		return AllycsDumpCurrentProcessW(fileToDumpW, imagebase, entrypoint, fileResultW);
	}
	else
	{
		return AllycsDumpCurrentProcessW(0, imagebase, entrypoint, fileResultW);
	}
}

BOOL WINAPI AllycsDumpProcessA(DWORD_PTR pid, const char * fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char * fileResult)
{
	WCHAR fileToDumpW[MAX_PATH];
	WCHAR fileResultW[MAX_PATH];

	if (fileResult == 0)
	{
		return FALSE;
	}

	if (MultiByteToWideChar(CP_ACP, 0, fileResult, -1, fileResultW, _countof(fileResultW)) == 0)
	{
		return FALSE;
	}

	if (fileToDump != 0)
	{
		if (MultiByteToWideChar(CP_ACP, 0, fileToDump, -1, fileToDumpW, _countof(fileToDumpW)) == 0)
		{
			return FALSE;
		}

		return AllycsDumpProcessW(pid, fileToDumpW, imagebase, entrypoint, fileResultW);
	}
	else
	{
		return AllycsDumpProcessW(pid, 0, imagebase, entrypoint, fileResultW);
	}
}

INT WINAPI AllycsStartGui(DWORD dwProcessId, HINSTANCE mod, DWORD_PTR entrypoint)
{
	GUI_DLL_PARAMETER guiParam;
	guiParam.dwProcessId = dwProcessId;
	guiParam.mod = mod;
	guiParam.entrypoint = entrypoint;

	return InitializeGui(hDllModule, (LPARAM)&guiParam);
}

int WINAPI AllycsIatSearch(DWORD dwProcessId, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch)
{
	ApiReader apiReader;
	ProcessLister processLister;
	Process *processPtr = 0;
	IATSearch iatSearch;

	std::vector<Process>& processList = processLister.getProcessListSnapshotNative();
	for(std::vector<Process>::iterator it = processList.begin(); it != processList.end(); ++it)
	{
		if(it->PID == dwProcessId)
		{
			processPtr = &(*it);
			break;
		}
	}

	if(!processPtr) return ALL_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
	{
		return ALL_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

	ProcessAccessHelp::selectedModule = 0;
	ProcessAccessHelp::targetImageBase = processPtr->imageBase;
	ProcessAccessHelp::targetSizeOfImage = processPtr->imageSize;

	apiReader.readApisFromModuleList();

	int retVal = ALL_ERROR_IATNOTFOUND;

	if (advancedSearch)
	{
		if (iatSearch.searchImportAddressTableInProcess(searchStart, iatStart, iatSize, true))
		{
			retVal = ALL_ERROR_SUCCESS;
		}
	}
	else
	{
		if (iatSearch.searchImportAddressTableInProcess(searchStart, iatStart, iatSize, false))
		{
			retVal = ALL_ERROR_SUCCESS;
		}
	}

	processList.clear();
	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	return retVal;
}


int WINAPI AllycsIatFixAutoW(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixFile)
{
	ApiReader apiReader;
	ProcessLister processLister;
	Process *processPtr = 0;
	std::map<DWORD_PTR, ImportModuleThunk> moduleList;

	std::vector<Process>& processList = processLister.getProcessListSnapshotNative();
	for(std::vector<Process>::iterator it = processList.begin(); it != processList.end(); ++it)
	{
		if(it->PID == dwProcessId)
		{
			processPtr = &(*it);
			break;
		}
	}

	if(!processPtr) return ALL_ERROR_PIDNOTFOUND;

	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	if (!ProcessAccessHelp::openProcessHandle(processPtr->PID))
	{
		return ALL_ERROR_PROCOPEN;
	}

	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

	ProcessAccessHelp::selectedModule = 0;
	ProcessAccessHelp::targetImageBase = processPtr->imageBase;
	ProcessAccessHelp::targetSizeOfImage = processPtr->imageSize;

	apiReader.readApisFromModuleList();

	apiReader.readAndParseIAT(iatAddr, iatSize, moduleList);

	//add IAT section to dump
	ImportRebuilder importRebuild(dumpFile);
	importRebuild.enableOFTSupport();

	int retVal = ALL_ERROR_IATWRITE;

	if (importRebuild.rebuildImportTable(iatFixFile, moduleList))
	{
		retVal = ALL_ERROR_SUCCESS;
	}

	processList.clear();
	moduleList.clear();
	ProcessAccessHelp::closeProcessHandle();
	apiReader.clearAll();

	return retVal;
}
