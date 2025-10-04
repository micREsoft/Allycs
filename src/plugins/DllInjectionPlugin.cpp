#include <plugins/DllInjectionPlugin.h>
#include <app/Allycs.h>

const WCHAR * DllInjectionPlugin::FILE_MAPPING_NAME = L"AllycsPluginExchange";

HANDLE DllInjectionPlugin::hProcess = 0;

//#define DEBUG_COMMENTS

void DllInjectionPlugin::injectPlugin(Plugin & plugin, std::map<DWORD_PTR, ImportModuleThunk> & moduleList, DWORD_PTR imageBase, DWORD_PTR imageSize)
{
	PALLYCS_EXCHANGE allycsExchange = 0;
	PUNRESOLVED_IMPORT unresImp = 0;

	BYTE * dataBuffer = 0;
	DWORD_PTR numberOfUnresolvedImports = getNumberOfUnresolvedImports(moduleList);

	if (numberOfUnresolvedImports == 0)
	{
		Allycs::windowLog.log(L"No unresolved Imports");
		return;
	}

	if (!createFileMapping((DWORD)(sizeof(ALLYCS_EXCHANGE) + sizeof(UNRESOLVED_IMPORT) + (sizeof(UNRESOLVED_IMPORT) * numberOfUnresolvedImports))))
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"injectPlugin :: createFileMapping %X failed",sizeof(ALLYCS_EXCHANGE) + sizeof(UNRESOLVED_IMPORT) + (sizeof(UNRESOLVED_IMPORT) * numberOfUnresolvedImports));
#endif
		return;
	}

	allycsExchange = (PALLYCS_EXCHANGE)lpViewOfFile;
	allycsExchange->status = 0xFF;
	allycsExchange->imageBase = imageBase;
	allycsExchange->imageSize = imageSize;
	allycsExchange->numberOfUnresolvedImports = numberOfUnresolvedImports;
	allycsExchange->offsetUnresolvedImportsArray = sizeof(ALLYCS_EXCHANGE);

	unresImp = (PUNRESOLVED_IMPORT)((DWORD_PTR)lpViewOfFile + sizeof(ALLYCS_EXCHANGE));

	addUnresolvedImports(unresImp, moduleList);

	SysIndirectUnmapViewOfSection((HANDLE)-1, lpViewOfFile);
	lpViewOfFile = 0;

	HMODULE hDll = dllInjection(hProcess, plugin.fullpath);
	if (hDll)
	{
		Allycs::windowLog.log(L"Plugin injection was successful");
		if (!unloadDllInProcess(hProcess,hDll))
		{
			Allycs::windowLog.log(L"Plugin unloading failed");
		}
		lpViewOfFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		if (lpViewOfFile)
		{
			allycsExchange = (PALLYCS_EXCHANGE)lpViewOfFile;
			handlePluginResults(allycsExchange, moduleList);
		}

	}
	else
	{
		Allycs::windowLog.log(L"Plugin injection failed");
	}

	closeAllHandles();
}

void DllInjectionPlugin::injectImprecPlugin(Plugin & plugin, std::map<DWORD_PTR, ImportModuleThunk> & moduleList, DWORD_PTR imageBase, DWORD_PTR imageSize)
{
	Plugin newPlugin;
	size_t mapSize = (wcslen(plugin.fullpath) + 1) * sizeof(WCHAR);

	HANDLE hImprecMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE|SEC_COMMIT, 0, (DWORD)mapSize, TEXT(PLUGIN_IMPREC_EXCHANGE_DLL_PATH));
	
	if (hImprecMap == NULL)
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"injectImprecPlugin :: CreateFileMapping failed 0x%X", GetLastError());
#endif
		return;
	}

	LPVOID lpImprecViewOfFile = MapViewOfFile(hImprecMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (lpImprecViewOfFile == NULL)
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"injectImprecPlugin :: MapViewOfFile failed 0x%X", GetLastError());
#endif
		SysIndirectClose(hImprecMap);
		return;
	}

	CopyMemory(lpImprecViewOfFile,plugin.fullpath, mapSize);

	SysIndirectUnmapViewOfSection((HANDLE)-1, lpImprecViewOfFile);

	newPlugin.fileSize = plugin.fileSize;
	wcscpy_s(newPlugin.pluginName, plugin.pluginName);
	wcscpy_s(newPlugin.fullpath, Allycs::plugins.imprecWrapperDllPath);

	injectPlugin(newPlugin,moduleList,imageBase,imageSize);

	SysIndirectClose(hImprecMap);
}



bool DllInjectionPlugin::createFileMapping(DWORD mappingSize)
{
	hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE|SEC_COMMIT, 0, mappingSize, FILE_MAPPING_NAME);

	if (hMapFile == NULL)
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"createFileMapping :: CreateFileMapping failed 0x%X", GetLastError());
#endif
		return false;
	}

	lpViewOfFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (lpViewOfFile == NULL)
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"createFileMapping :: MapViewOfFile failed 0x%X", GetLastError());
#endif
		SysIndirectClose(hMapFile);
		hMapFile = 0;
		return false;
	}
	else
	{
		return true;
	}
}

void DllInjectionPlugin::closeAllHandles()
{
	if (lpViewOfFile)
	{
		SysIndirectUnmapViewOfSection((HANDLE)-1, lpViewOfFile);
		lpViewOfFile = 0;
	}
	if (hMapFile)
	{
		SysIndirectClose(hMapFile);
		hMapFile = 0;
	}
}

DWORD_PTR DllInjectionPlugin::getNumberOfUnresolvedImports( std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	std::map<DWORD_PTR, ImportThunk>::iterator iterator2;
	ImportModuleThunk * moduleThunk = 0;
	ImportThunk * importThunk = 0;
	DWORD_PTR dwNumber = 0;

	iterator1 = moduleList.begin();

	while (iterator1 != moduleList.end())
	{
		moduleThunk = &(iterator1->second);

		iterator2 = moduleThunk->thunkList.begin();

		while (iterator2 != moduleThunk->thunkList.end())
		{
			importThunk = &(iterator2->second);

			if (importThunk->valid == false)
			{
				dwNumber++;
			}

			iterator2++;
		}

		iterator1++;
	}

	return dwNumber;
}

void DllInjectionPlugin::addUnresolvedImports( PUNRESOLVED_IMPORT firstUnresImp, std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	std::map<DWORD_PTR, ImportThunk>::iterator iterator2;
	ImportModuleThunk * moduleThunk = 0;
	ImportThunk * importThunk = 0;

	iterator1 = moduleList.begin();

	while (iterator1 != moduleList.end())
	{
		moduleThunk = &(iterator1->second);

		iterator2 = moduleThunk->thunkList.begin();

		while (iterator2 != moduleThunk->thunkList.end())
		{
			importThunk = &(iterator2->second);

			if (importThunk->valid == false)
			{
				firstUnresImp->InvalidApiAddress = importThunk->apiAddressVA;
				firstUnresImp->ImportTableAddressPointer = importThunk->va;
				firstUnresImp++;
			}

			iterator2++;
		}

		iterator1++;
	}

	firstUnresImp->InvalidApiAddress = 0;
	firstUnresImp->ImportTableAddressPointer = 0;
}

void DllInjectionPlugin::handlePluginResults( PALLYCS_EXCHANGE allycsExchange, std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
{
	PUNRESOLVED_IMPORT unresImp = (PUNRESOLVED_IMPORT)((DWORD_PTR)allycsExchange + allycsExchange->offsetUnresolvedImportsArray);;

	switch (allycsExchange->status)
	{
	case ALLYCS_STATUS_SUCCESS:
		Allycs::windowLog.log(L"Plugin was successful");
		updateImportsWithPluginResult(unresImp, moduleList);
		break;
	case ALLYCS_STATUS_UNKNOWN_ERROR:
		Allycs::windowLog.log(L"Plugin reported Unknown Error");
		break;
	case ALLYCS_STATUS_UNSUPPORTED_PROTECTION:
		Allycs::windowLog.log(L"Plugin detected unknown protection");
		updateImportsWithPluginResult(unresImp, moduleList);
		break;
	case ALLYCS_STATUS_IMPORT_RESOLVING_FAILED:
		Allycs::windowLog.log(L"Plugin import resolving failed");
		updateImportsWithPluginResult(unresImp, moduleList);
		break;
	case ALLYCS_STATUS_MAPPING_FAILED:
		Allycs::windowLog.log(L"Plugin file mapping failed");
		break;
	default:
		Allycs::windowLog.log(L"Plugin failed without reason");
	}
}

void DllInjectionPlugin::updateImportsWithPluginResult( PUNRESOLVED_IMPORT firstUnresImp, std::map<DWORD_PTR, ImportModuleThunk> & moduleList )
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;
	std::map<DWORD_PTR, ImportThunk>::iterator iterator2;
	ImportModuleThunk * moduleThunk = 0;
	ImportThunk * importThunk = 0;
	ApiInfo * apiInfo = 0;
	bool isSuspect = 0;

	iterator1 = moduleList.begin();

	while (iterator1 != moduleList.end())
	{
		moduleThunk = &(iterator1->second);

		iterator2 = moduleThunk->thunkList.begin();

		while (iterator2 != moduleThunk->thunkList.end())
		{
			importThunk = &(iterator2->second);

			if (importThunk->valid == false)
			{
				if (apiReader->isApiAddressValid(firstUnresImp->InvalidApiAddress))
				{
					apiInfo = apiReader->getApiByVirtualAddress(firstUnresImp->InvalidApiAddress,&isSuspect);

					importThunk->suspect = isSuspect;
					importThunk->valid = true;
					importThunk->apiAddressVA = firstUnresImp->InvalidApiAddress;
					importThunk->hint = (WORD)apiInfo->hint;
					importThunk->ordinal = apiInfo->ordinal;
					strcpy_s(importThunk->name, apiInfo->name);
					wcscpy_s(importThunk->moduleName, apiInfo->module->getFilename());

					if (moduleThunk->moduleName[0] == L'?')
					{
						wcscpy_s(moduleThunk->moduleName, _countof(importThunk->moduleName), apiInfo->module->getFilename());
					}
				}
				
				firstUnresImp++;
			}

			iterator2++;
		}

		iterator1++;
	}
}