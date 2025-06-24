#pragma once

#include "utils/ConfigurationHolder.h"
#include "plugins/PluginLoader.h"
#include "injection/ProcessLister.h"
#include "utils/Logger.h"

#define APPNAME_S "Allycs"
#define APPVERSION_S "v2.0.0"
#define APPVERSIONDWORD 0x00009800

#define DONATE_BTC_ADDRESS "bc1qj8lsw8xfdsw3vnk3ur3kk6439cea65rxrgernz"

#define APPNAME TEXT(APPNAME_S)
#define APPVERSION TEXT(APPVERSION_S)

class Allycs
{
public:

	static void initAsGuiApp();
	static void initAsDll();

	static ConfigurationHolder config;
	static PluginLoader plugins;

	static ProcessLister processLister;

	static FileLog debugLog;
	static ListboxLog windowLog;

private:

	static const WCHAR DEBUG_LOG_FILENAME[];
};
