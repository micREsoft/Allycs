#pragma once

#include <syscaller.h>
#include <vector>

class Plugin {
public:
	DWORD fileSize;
	WCHAR fullpath[MAX_PATH];
	WCHAR pluginName[MAX_PATH];
};

typedef wchar_t * (__cdecl * def_AllycsPluginNameW)();
typedef char * (__cdecl * def_AllycsPluginNameA)();

typedef DWORD ( * def_Imprec_Trace)(DWORD hFileMap, DWORD dwSizeMap, DWORD dwTimeOut, DWORD dwToTrace, DWORD dwExactCall);

class PluginLoader {
public:
	WCHAR imprecWrapperDllPath[MAX_PATH];

	bool findAllPlugins();

	std::vector<Plugin> & getAllycsPluginList();
	std::vector<Plugin> & getImprecPluginList();

private:

	static const WCHAR PLUGIN_DIR[];
	static const WCHAR PLUGIN_SEARCH_STRING[];
	static const WCHAR PLUGIN_IMPREC_DIR[];
	static const WCHAR PLUGIN_IMPREC_WRAPPER_DLL[];

	std::vector<Plugin> allycsPluginList;
	std::vector<Plugin> imprecPluginList;

	WCHAR dirSearchString[MAX_PATH];
	WCHAR baseDirPath[MAX_PATH];

	bool buildSearchString();
	bool buildSearchStringImprecPlugins();

	bool getAllycsPluginName(Plugin * pluginData);
	bool searchForPlugin(std::vector<Plugin> & newPluginList, const WCHAR * searchPath, bool isAllycsPlugin);

	static bool fileExists(const WCHAR * fileName);
	static bool isValidDllFile(const WCHAR * fullpath);
	static bool isValidImprecPlugin(const WCHAR * fullpath);
};
