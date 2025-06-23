#include "gui/OptionsGui.h"
#include "app/Allycs.h"

BOOL OptionsGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
	loadOptions();
	DoDataExchange(DDX_LOAD); // show settings

	EditSectionName.LimitText(IMAGE_SIZEOF_SHORT_NAME);

	CenterWindow();

	return TRUE;
}

void OptionsGui::OnOK(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	DoDataExchange(DDX_SAVE);
	saveOptions();
	Allycs::config.saveConfiguration();

	EndDialog(0);
}

void OptionsGui::OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	EndDialog(0);
}

void OptionsGui::saveOptions() const
{
	Allycs::config[USE_PE_HEADER_FROM_DISK].setBool(usePEHeaderFromDisk);
	Allycs::config[DEBUG_PRIVILEGE].setBool(debugPrivilege);
	Allycs::config[CREATE_BACKUP].setBool(createBackup);
	Allycs::config[DLL_INJECTION_AUTO_UNLOAD].setBool(dllInjectionAutoUnload);
	Allycs::config[UPDATE_HEADER_CHECKSUM].setBool(updateHeaderChecksum);
	Allycs::config[IAT_SECTION_NAME].setString(iatSectionName);
	Allycs::config[REMOVE_DOS_HEADER_STUB].setBool(removeDosHeaderStub);
	Allycs::config[IAT_FIX_AND_OEP_FIX].setBool(fixIatAndOep);
	Allycs::config[SUSPEND_PROCESS_FOR_DUMPING].setBool(suspendProcessForDumping);
	Allycs::config[OriginalFirstThunk_SUPPORT].setBool(oftSupport);
	Allycs::config[USE_ADVANCED_IAT_SEARCH].setBool(useAdvancedIatSearch);
	Allycs::config[SCAN_DIRECT_IMPORTS].setBool(scanDirectImports);
	Allycs::config[FIX_DIRECT_IMPORTS_NORMAL].setBool(fixDirectImportsNormal);
	Allycs::config[FIX_DIRECT_IMPORTS_UNIVERSAL].setBool(fixDirectImportsUniversal);
	Allycs::config[CREATE_NEW_IAT_IN_SECTION].setBool(createNewIatInSection);
    Allycs::config[DONT_CREATE_NEW_SECTION].setBool(dontCreateNewSection);
    Allycs::config[APIS_ALWAYS_FROM_DISK].setBool(readApisAlwaysFromDisk);
    Allycs::config[DARK_MODE].setBool(darkMode);
    Allycs::config[DONT_COMPACT_RAW_DATA].setBool(dontCompactRawData);
}

void OptionsGui::loadOptions()
{
	usePEHeaderFromDisk    = Allycs::config[USE_PE_HEADER_FROM_DISK].getBool();
	debugPrivilege         = Allycs::config[DEBUG_PRIVILEGE].getBool();
	createBackup           = Allycs::config[CREATE_BACKUP].getBool();
	dllInjectionAutoUnload = Allycs::config[DLL_INJECTION_AUTO_UNLOAD].getBool();
	updateHeaderChecksum   = Allycs::config[UPDATE_HEADER_CHECKSUM].getBool();
	wcsncpy_s(iatSectionName, Allycs::config[IAT_SECTION_NAME].getString(), _countof(iatSectionName)-1);
	iatSectionName[_countof(iatSectionName) - 1] = L'\0';

	removeDosHeaderStub = Allycs::config[REMOVE_DOS_HEADER_STUB].getBool();
	fixIatAndOep = Allycs::config[IAT_FIX_AND_OEP_FIX].getBool();
	suspendProcessForDumping = Allycs::config[SUSPEND_PROCESS_FOR_DUMPING].getBool();
	oftSupport = Allycs::config[OriginalFirstThunk_SUPPORT].getBool();
	useAdvancedIatSearch = Allycs::config[USE_ADVANCED_IAT_SEARCH].getBool();
	scanDirectImports = Allycs::config[SCAN_DIRECT_IMPORTS].getBool();
	fixDirectImportsNormal = Allycs::config[FIX_DIRECT_IMPORTS_NORMAL].getBool();
	fixDirectImportsUniversal = Allycs::config[FIX_DIRECT_IMPORTS_UNIVERSAL].getBool();
	createNewIatInSection = Allycs::config[CREATE_NEW_IAT_IN_SECTION].getBool();
    dontCreateNewSection = Allycs::config[DONT_CREATE_NEW_SECTION].getBool();
    readApisAlwaysFromDisk = Allycs::config[APIS_ALWAYS_FROM_DISK].getBool();
    darkMode = Allycs::config[DARK_MODE].getBool();
    dontCompactRawData = Allycs::config[DONT_COMPACT_RAW_DATA].getBool();
}
