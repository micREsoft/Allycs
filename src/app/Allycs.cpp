#include "app/Allycs.h"
#include "core/AllycsApi.h"
#include "utils/SystemInformation.h"
#include "core/ProcessAccessHelp.h"

ConfigurationHolder Allycs::config(L"Allycs.ini");
PluginLoader Allycs::plugins;

ProcessLister Allycs::processLister;

const WCHAR Allycs::DEBUG_LOG_FILENAME[] = L"Allycs_debug.log";

FileLog Allycs::debugLog(DEBUG_LOG_FILENAME);
ListboxLog Allycs::windowLog;

void Allycs::initAsGuiApp()
{
	// First initialize the API layer
	AllycsApi::initialize();
	
	// Then load configuration
	config.loadConfiguration();
	
	// Get system information before loading plugins
	SystemInformation::getSystemInformation();
	
	// Load modules list before plugins
	ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
	
	// Now it's safe to find plugins
	plugins.findAllPlugins();

	if(config[DEBUG_PRIVILEGE].isTrue())
	{
		processLister.setDebugPrivileges();
	}
}

void Allycs::initAsDll()
{
	AllycsApi::initialize();
	ProcessAccessHelp::ownModuleList.clear();
	SystemInformation::getSystemInformation();
	ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
}